//! Subdocs snapshot index management.
//!
//! Walks `filemeta_v0` on a shared folder doc, fetches each child y-doc that
//! exists in storage, encodes its snapshot, and writes
//! `subdocs[child_guid] = { snapshot, last_edit }` into the folder's metadata.
//! `last_edit` per child is the `modified_at` timestamp embedded in that
//! child's `data.ysweet` envelope.
//!
//! Storage layout assumed: `<store>/<relay_id>-<doc_guid>/data.ysweet`.

use anyhow::{anyhow, Context, Result};
use futures::stream::{self, StreamExt};
use std::collections::HashSet;
use std::sync::Arc;
use y_sweet_core::doc_connection::DOC_NAME;
use y_sweet_core::doc_sync::DocWithSyncKv;
use y_sweet_core::store::Store;
use y_sweet_core::sync_kv::SyncKv;
use yrs::{updates::encoder::Encode, Map, Out, ReadTxn, Transact};
use yrs_kvstore::DocOps;

/// Whitelist of `filemeta_v0` types that have their own y-doc in storage.
/// Other types (image/pdf/file/video/folder/base) don't have a `data.ysweet`,
/// so we skip them without making any S3 request.
const TYPES_WITH_DOCS: &[&str] = &["markdown", "canvas"];

const FETCH_CONCURRENCY: usize = 16;

/// Per-child fetch result handed back to the serial collator.
enum ChildOutcome {
    Ok {
        snapshot_bytes: Vec<u8>,
        last_modified_ms: u64,
    },
    Missing,
    Skipped,
    Error(String),
}

pub async fn run_backfill(
    store: Arc<Box<dyn Store>>,
    relay_id: &str,
    folder_guid: &str,
    check_only: bool,
    dry_run: bool,
) -> Result<()> {
    if check_only {
        eprintln!("CHECK: reporting current index coverage only — no fetches or writes.");
    } else if dry_run {
        eprintln!(
            "DRY RUN: snapshots will be computed but the parent folder will not be mutated or persisted."
        );
    }

    store.init().await.context("store init failed")?;

    let folder_key = format!("{}-{}", relay_id, folder_guid);
    let folder = DocWithSyncKv::new(&folder_key, Some(store.clone()), || (), None)
        .await
        .context("failed to load folder doc")?;

    let children = read_filemeta_children(&folder);
    println!("folder = {}", folder_guid);
    println!("filemeta_v0 unique child guids = {}", children.len());

    print_index_coverage(&folder, &children);

    if check_only {
        return Ok(());
    }

    let mut present = 0usize;
    let mut missing = 0usize;
    let mut skipped_by_type = 0usize;
    let mut sizes: Vec<usize> = Vec::with_capacity(children.len());
    let mut by_type: std::collections::BTreeMap<String, (usize, usize, usize)> =
        std::collections::BTreeMap::new();
    let mut errors = 0usize;

    for (_, child_type) in &children {
        let type_label = child_type.clone().unwrap_or_else(|| "<none>".to_string());
        by_type.entry(type_label).or_insert((0, 0, 0)).0 += 1;
    }

    let total = children.len();
    let total_children = children.len();
    let store_for_tasks = store.clone();
    let relay_id_for_tasks = relay_id.to_string();

    let mut stream = stream::iter(children.into_iter().enumerate())
        .map(move |(i, (child_guid, child_type))| {
            let store = store_for_tasks.clone();
            let relay_id = relay_id_for_tasks.clone();
            async move {
                let type_label = child_type.clone().unwrap_or_else(|| "<none>".to_string());
                let has_doc = child_type
                    .as_deref()
                    .map(|t| TYPES_WITH_DOCS.contains(&t))
                    .unwrap_or(false);

                if !has_doc {
                    return (i, child_guid, type_label, ChildOutcome::Skipped);
                }

                let child_key = format!("{}-{}", relay_id, child_guid);
                let data_key = format!("{}/data.ysweet", child_key);

                let bytes = match store.get(&data_key).await {
                    Ok(Some(b)) => b,
                    Ok(None) => {
                        return (i, child_guid, type_label, ChildOutcome::Missing);
                    }
                    Err(e) => {
                        return (
                            i,
                            child_guid,
                            type_label,
                            ChildOutcome::Error(format!("get failed: {e}")),
                        );
                    }
                };

                let (sync_kv, modified_at) = match SyncKv::from_bytes(&bytes, &child_key) {
                    Ok(v) => v,
                    Err(e) => {
                        return (
                            i,
                            child_guid,
                            type_label,
                            ChildOutcome::Error(format!("decode failed: {e}")),
                        );
                    }
                };

                let doc = yrs::Doc::new();
                {
                    let mut txn = doc.transact_mut();
                    if let Err(e) = sync_kv.load_doc(DOC_NAME, &mut txn) {
                        return (
                            i,
                            child_guid,
                            type_label,
                            ChildOutcome::Error(format!("load_doc failed: {e:?}")),
                        );
                    }
                }
                let snapshot_bytes = doc.transact().snapshot().encode_v1();

                let last_modified_ms = modified_at.unwrap_or(0);

                (
                    i,
                    child_guid,
                    type_label,
                    ChildOutcome::Ok {
                        snapshot_bytes,
                        last_modified_ms,
                    },
                )
            }
        })
        .buffer_unordered(FETCH_CONCURRENCY);

    let mut completed = 0usize;
    while let Some((_i, child_guid, type_label, outcome)) = stream.next().await {
        let counters = by_type.get_mut(&type_label).expect("type pre-tallied");
        completed += 1;

        match outcome {
            ChildOutcome::Ok {
                snapshot_bytes,
                last_modified_ms,
            } => {
                let snap_len = snapshot_bytes.len();
                if !dry_run {
                    folder.update_subdoc_snapshot_at(&child_guid, snapshot_bytes, last_modified_ms);
                }
                sizes.push(snap_len);
                counters.2 += snap_len;
                present += 1;
            }
            ChildOutcome::Missing => {
                missing += 1;
                counters.1 += 1;
            }
            ChildOutcome::Skipped => {
                skipped_by_type += 1;
            }
            ChildOutcome::Error(msg) => {
                eprintln!("{child_guid}: {msg}");
                errors += 1;
            }
        }

        if completed % 200 == 0 {
            eprintln!("[{completed}/{total}] processed");
        }
    }

    if dry_run {
        eprintln!("DRY RUN: skipping persist of parent folder.");
    } else {
        eprintln!("persisting parent folder with write lease...");
        folder
            .sync_kv()
            .persist_if_unchanged()
            .await
            .map_err(|e| anyhow!("lease-protected persist failed: {e}"))?;
        eprintln!("persist complete");
    }

    sizes.sort_unstable();

    let sum: usize = sizes.iter().sum();
    let min = sizes.first().copied().unwrap_or(0);
    let max = sizes.last().copied().unwrap_or(0);
    let p = |q: f64| -> usize {
        if sizes.is_empty() {
            0
        } else {
            let idx = ((sizes.len() as f64 - 1.0) * q).round() as usize;
            sizes[idx]
        }
    };
    let mean = if sizes.is_empty() {
        0
    } else {
        sum / sizes.len()
    };

    println!();
    println!("children processed       = {}", present);
    println!("children missing         = {}", missing);
    println!("skipped by type filter   = {}", skipped_by_type);
    println!("load errors              = {}", errors);
    println!();
    println!("snapshot size bytes:");
    println!("  count = {}", sizes.len());
    println!(
        "  sum   = {}  ({:.2} MiB)",
        sum,
        sum as f64 / 1024.0 / 1024.0
    );
    println!("  mean  = {}", mean);
    println!("  min   = {}", min);
    println!("  p50   = {}", p(0.50));
    println!("  p90   = {}", p(0.90));
    println!("  p99   = {}", p(0.99));
    println!("  max   = {}", max);

    println!();
    println!("by filemeta_v0 type:");
    for (typ, (count, miss, snap_sum)) in &by_type {
        println!(
            "  {:>10}: count={} missing={} snapshot_bytes={} (mean={})",
            typ,
            count,
            miss,
            snap_sum,
            if count - miss > 0 {
                snap_sum / (count - miss)
            } else {
                0
            }
        );
    }

    if !sizes.is_empty() {
        println!();
        println!("size histogram (10 buckets, log-ish):");
        let buckets: [(usize, usize); 10] = [
            (0, 256),
            (256, 1024),
            (1024, 2048),
            (2048, 4096),
            (4096, 8192),
            (8192, 16384),
            (16384, 32768),
            (32768, 65536),
            (65536, 131072),
            (131072, usize::MAX),
        ];
        for (lo, hi) in buckets {
            let n = sizes.iter().filter(|s| **s >= lo && **s < hi).count();
            let bar = "#".repeat((n * 60 / sizes.len().max(1)).min(60));
            let label = if hi == usize::MAX {
                format!("{}+", lo)
            } else {
                format!("{}..{}", lo, hi)
            };
            println!("  {:>14} : {:>6}  {}", label, n, bar);
        }
    }

    let folder_data_len: u64 = store
        .list(&format!("{}/", folder_key))
        .await
        .ok()
        .and_then(|files| {
            files
                .into_iter()
                .find(|f| f.key.ends_with("data.ysweet"))
                .map(|f| f.size)
        })
        .unwrap_or(0);

    let cbor_overhead_per_entry = 64;
    let projected_index_bytes = sum + cbor_overhead_per_entry * sizes.len() + 32 * total_children;

    println!();
    println!(
        "current folder data.ysweet on disk = {} bytes",
        folder_data_len
    );
    println!(
        "projected metadata.subdocs index   = {} bytes ({:.2} MiB)",
        projected_index_bytes,
        projected_index_bytes as f64 / 1024.0 / 1024.0,
    );
    println!(
        "projected total folder blob        = {} bytes ({:.2} MiB)",
        folder_data_len as usize + projected_index_bytes,
        (folder_data_len as usize + projected_index_bytes) as f64 / 1024.0 / 1024.0,
    );

    Ok(())
}

fn read_filemeta_children(doc: &DocWithSyncKv) -> Vec<(String, Option<String>)> {
    let aw = doc.awareness();
    let aw = aw.read().unwrap();
    let yd = &aw.doc;

    let has_filemeta = {
        let txn = yd.transact();
        txn.root_refs().any(|(name, _)| name == "filemeta_v0")
    };
    if !has_filemeta {
        return Vec::new();
    }

    let fm_map = yd.get_or_insert_map("filemeta_v0");
    let txn = yd.transact();

    let mut seen: HashSet<String> = HashSet::new();
    let mut out: Vec<(String, Option<String>)> = Vec::new();

    for (_path, value) in fm_map.iter(&txn) {
        if let Out::Any(yrs::Any::Map(m)) = value {
            let id = m.get("id").and_then(|v| match v {
                yrs::Any::String(s) => Some(s.to_string()),
                _ => None,
            });
            let typ = m.get("type").and_then(|v| match v {
                yrs::Any::String(s) => Some(s.to_string()),
                _ => None,
            });
            if let Some(guid) = id {
                if seen.insert(guid.clone()) {
                    out.push((guid, typ));
                }
            }
        }
    }

    out
}

/// Read the parent folder's existing `metadata.subdocs` map and report
/// coverage stats: filemeta_v0 entries covered, orphans (entries in the
/// index without a matching filemeta_v0 entry), and `last_edit` timestamp
/// distribution. Useful for spotting whether the runtime has overwritten
/// backfilled entries with current-time stamps.
fn print_index_coverage(folder: &DocWithSyncKv, children: &[(String, Option<String>)]) {
    use std::collections::BTreeMap;

    let metadata = folder.sync_kv().get_metadata().unwrap_or_default();
    let mut index_entries: BTreeMap<String, (usize, Option<u64>)> = BTreeMap::new();

    if let Some(ciborium::value::Value::Map(entries)) = metadata.get("subdocs") {
        for (k, v) in entries {
            let id = match k {
                ciborium::value::Value::Text(s) => s.clone(),
                _ => continue,
            };
            let mut snap_len = 0usize;
            let mut last_edit: Option<u64> = None;
            if let ciborium::value::Value::Map(fields) = v {
                for (fk, fv) in fields {
                    if let ciborium::value::Value::Text(name) = fk {
                        match (name.as_str(), fv) {
                            ("snapshot", ciborium::value::Value::Bytes(b)) => snap_len = b.len(),
                            ("last_edit", ciborium::value::Value::Integer(i)) => {
                                last_edit = i128::from(*i).try_into().ok();
                            }
                            _ => {}
                        }
                    }
                }
            }
            index_entries.insert(id, (snap_len, last_edit));
        }
    }

    let filemeta_set: std::collections::HashSet<&str> =
        children.iter().map(|(g, _)| g.as_str()).collect();

    let mut by_type_total: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_type_covered: BTreeMap<String, usize> = BTreeMap::new();
    for (g, t) in children {
        let label = t.clone().unwrap_or_else(|| "<none>".to_string());
        *by_type_total.entry(label.clone()).or_insert(0) += 1;
        if index_entries.contains_key(g) {
            *by_type_covered.entry(label).or_insert(0) += 1;
        }
    }

    let orphans: Vec<&String> = index_entries
        .keys()
        .filter(|id| !filemeta_set.contains(id.as_str()))
        .collect();

    let mut last_edits: Vec<u64> = index_entries.values().filter_map(|(_, le)| *le).collect();
    last_edits.sort_unstable();

    let total_index = index_entries.len();
    let total_filemeta = children.len();
    let covered = total_index - orphans.len();

    println!();
    println!("=== current index coverage ===");
    println!("filemeta_v0 entries  = {}", total_filemeta);
    println!("metadata.subdocs ix  = {}", total_index);
    println!(
        "  matched filemeta   = {} ({:.1}% of filemeta)",
        covered,
        100.0 * covered as f64 / total_filemeta.max(1) as f64,
    );
    println!("  orphans (in ix only) = {}", orphans.len());

    println!("by filemeta_v0 type:");
    for (typ, total) in &by_type_total {
        let cov = by_type_covered.get(typ).copied().unwrap_or(0);
        println!(
            "  {:>10}: {:>5} total, {:>5} covered ({:.0}%)",
            typ,
            total,
            cov,
            if *total > 0 {
                100.0 * cov as f64 / *total as f64
            } else {
                0.0
            },
        );
    }

    if !last_edits.is_empty() {
        let p = |q: f64| -> u64 {
            let idx = ((last_edits.len() as f64 - 1.0) * q).round() as usize;
            last_edits[idx]
        };
        println!(
            "last_edit ms (n={}): min={} p50={} p99={} max={}",
            last_edits.len(),
            last_edits.first().copied().unwrap_or(0),
            p(0.50),
            p(0.99),
            last_edits.last().copied().unwrap_or(0),
        );
        let span_ms =
            last_edits.last().copied().unwrap_or(0) - last_edits.first().copied().unwrap_or(0);
        let span_days = span_ms as f64 / 1000.0 / 60.0 / 60.0 / 24.0;
        println!("  span = {:.1} days", span_days);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let recent_24h = last_edits
            .iter()
            .filter(|t| now_ms.saturating_sub(**t) < 24 * 60 * 60 * 1000)
            .count();
        let recent_1h = last_edits
            .iter()
            .filter(|t| now_ms.saturating_sub(**t) < 60 * 60 * 1000)
            .count();
        println!(
            "  entries with last_edit in last 24h = {}, last 1h = {}",
            recent_24h, recent_1h
        );
    } else {
        println!("last_edit timestamps: none recorded yet");
    }
    println!();
}
