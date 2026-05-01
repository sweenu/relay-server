use anyhow::{bail, Context, Result};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use y_sweet_core::doc_connection::DOC_NAME;
use y_sweet_core::store::{Store, StoreError};
use y_sweet_core::sync_kv::SyncKv;
use yrs::updates::decoder::Decode;
use yrs::{Any, Array, Doc, GetString, In, Map, Out, ReadTxn, StateVector, Transact, Update};
use yrs_kvstore::DocOps;

const INTERNAL_ROOTS: [&str; 1] = ["users"];

#[derive(Clone, Debug)]
struct RestoreTarget {
    doc_guid: String,
    version_id: String,
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct RootKey {
    root: String,
    key: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RootKind {
    Map,
    Array,
    Text,
}

impl RootKind {
    fn as_str(&self) -> &'static str {
        match self {
            RootKind::Map => "map",
            RootKind::Array => "array",
            RootKind::Text => "text",
        }
    }
}

#[derive(Clone, Debug)]
struct RootInfo {
    name: String,
    kind: RootKind,
    size: String,
    supported: bool,
    internal: bool,
}

#[derive(Clone, Debug)]
struct RootSelection {
    discovered: Vec<RootInfo>,
    map_roots: Vec<String>,
    unsupported_selected: Vec<RootInfo>,
}

pub async fn run(
    store: Arc<Box<dyn Store>>,
    relay_guid: &str,
    doc_guid: &str,
    version_id: &str,
    only: &[String],
    except: &[String],
    write: bool,
    verify: bool,
) -> Result<()> {
    let only = normalize_root_filter(only, "--only")?;
    let except = normalize_root_filter(except, "--except")?;
    if !only.is_empty() && !except.is_empty() {
        bail!("--only and --except cannot be used together");
    }

    let target = RestoreTarget {
        doc_guid: doc_guid.to_string(),
        version_id: version_id.to_string(),
    };

    store.init().await?;

    println!(
        "mode={} doc={} from-version={}",
        if verify {
            "verify"
        } else if write {
            "write"
        } else {
            "dry-run"
        },
        doc_guid,
        version_id
    );

    if verify {
        verify_one(store, relay_guid, &target, &only, &except).await
    } else {
        repair_one(store, relay_guid, &target, &only, &except, write).await
    }
}

fn normalize_root_filter(roots: &[String], flag: &str) -> Result<BTreeSet<String>> {
    let mut seen = BTreeSet::new();

    for root in roots {
        let root = root.trim();
        if root.is_empty() {
            bail!("{} root names must be non-empty", flag);
        }
        seen.insert(root.to_string());
    }

    Ok(seen)
}

fn select_source_roots(
    source_doc: &Doc,
    only: &BTreeSet<String>,
    except: &BTreeSet<String>,
) -> Result<RootSelection> {
    let discovered = discover_roots(source_doc);
    if discovered.is_empty() {
        bail!("source version contains no top-level roots");
    }

    let discovered_names = discovered
        .iter()
        .map(|root| root.name.clone())
        .collect::<BTreeSet<_>>();
    let missing_only = only
        .difference(&discovered_names)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_only.is_empty() {
        bail!("unknown --only roots: {}", missing_only.join(","));
    }
    let missing_except = except
        .difference(&discovered_names)
        .cloned()
        .collect::<Vec<_>>();
    if !missing_except.is_empty() {
        bail!("unknown --except roots: {}", missing_except.join(","));
    }

    let selected = discovered
        .iter()
        .filter(|root| {
            if !only.is_empty() {
                only.contains(&root.name)
            } else {
                !root.internal && !except.contains(&root.name)
            }
        })
        .cloned()
        .collect::<Vec<_>>();
    if selected.is_empty() {
        bail!("no roots selected");
    }

    let map_roots = selected
        .iter()
        .filter(|root| root.supported)
        .map(|root| root.name.clone())
        .collect::<Vec<_>>();
    let unsupported_selected = selected
        .into_iter()
        .filter(|root| !root.supported)
        .collect::<Vec<_>>();

    Ok(RootSelection {
        discovered,
        map_roots,
        unsupported_selected,
    })
}

fn discover_roots(doc: &Doc) -> Vec<RootInfo> {
    let txn = doc.transact();
    let root_names = txn
        .root_refs()
        .map(|(name, _)| name.to_string())
        .collect::<Vec<_>>();
    drop(txn);

    let mut roots = root_names
        .into_iter()
        .map(|name| describe_root(doc, &name))
        .collect::<Vec<_>>();
    roots.sort_by(|a, b| a.name.cmp(&b.name));
    roots
}

fn describe_root(doc: &Doc, name: &str) -> RootInfo {
    let internal = is_internal_root(name);
    let map = doc.get_or_insert_map(name);
    let txn = doc.transact();
    let mut map_entries = 0u32;
    let mut map_values_supported = true;
    for (_, value) in map.iter(&txn) {
        map_entries += 1;
        if !matches!(value, Out::Any(_)) {
            map_values_supported = false;
        }
    }
    drop(txn);

    if map_entries > 0 {
        return RootInfo {
            name: name.to_string(),
            kind: RootKind::Map,
            size: format!("{} entries", map_entries),
            supported: map_values_supported,
            internal,
        };
    }

    let text = doc.get_or_insert_text(name);
    let txn = doc.transact();
    let text_len = text.get_string(&txn).chars().count();
    drop(txn);
    if text_len > 0 {
        return RootInfo {
            name: name.to_string(),
            kind: RootKind::Text,
            size: format!("{} chars", text_len),
            supported: false,
            internal,
        };
    }

    let array = doc.get_or_insert_array(name);
    let txn = doc.transact();
    let array_len = array.len(&txn);
    drop(txn);
    if array_len > 0 {
        return RootInfo {
            name: name.to_string(),
            kind: RootKind::Array,
            size: format!("{} items", array_len),
            supported: false,
            internal,
        };
    }

    RootInfo {
        name: name.to_string(),
        kind: RootKind::Map,
        size: "0 entries".to_string(),
        supported: true,
        internal,
    }
}

fn is_internal_root(name: &str) -> bool {
    INTERNAL_ROOTS.contains(&name)
}

fn print_root_selection(selection: &RootSelection) {
    let selected_names = selection
        .map_roots
        .iter()
        .cloned()
        .chain(
            selection
                .unsupported_selected
                .iter()
                .map(|root| root.name.clone()),
        )
        .collect::<BTreeSet<_>>();

    println!("discovered roots:");
    for root in &selection.discovered {
        let selected = if selected_names.contains(&root.name) {
            "*"
        } else {
            " "
        };
        let internal = if root.internal { " internal" } else { "" };
        let unsupported = if root.supported { "" } else { " unsupported" };
        println!(
            "  {} {:<24} {:<12} {}{}{}",
            selected,
            root.name,
            root.kind.as_str(),
            root.size,
            internal,
            unsupported
        );
    }

    if selection.map_roots.is_empty() {
        println!("selected map roots=<none>");
    } else {
        println!("selected map roots={}", selection.map_roots.join(","));
    }
    if !selection.unsupported_selected.is_empty() {
        println!(
            "unsupported selected roots={}",
            selection
                .unsupported_selected
                .iter()
                .map(|root| format!("{}:{}", root.name, root.kind.as_str()))
                .collect::<Vec<_>>()
                .join(",")
        );
    }
}

fn ensure_selection_can_run(selection: &RootSelection, mode: &str) -> Result<()> {
    if !selection.unsupported_selected.is_empty() {
        bail!(
            "{} cannot continue with unsupported selected roots: {}. Use --only or --except to narrow the restore.",
            mode,
            selection
                .unsupported_selected
                .iter()
                .map(|root| format!("{}:{}", root.name, root.kind.as_str()))
                .collect::<Vec<_>>()
                .join(",")
        );
    }
    if selection.map_roots.is_empty() {
        bail!("{} has no supported roots to process", mode);
    }
    Ok(())
}

async fn verify_one(
    store: Arc<Box<dyn Store>>,
    relay_guid: &str,
    target: &RestoreTarget,
    only: &BTreeSet<String>,
    except: &BTreeSet<String>,
) -> Result<()> {
    let doc_key = format!("{}-{}", relay_guid, target.doc_guid);
    let storage_key = format!("{}/data.ysweet", doc_key);
    let source_bytes = store
        .get_version(&storage_key, &target.version_id)
        .await?
        .with_context(|| format!("missing version {} for {}", target.version_id, storage_key))?;
    let current_bytes = store
        .get(&storage_key)
        .await?
        .with_context(|| format!("missing current {}", storage_key))?;

    let source_doc = load_doc_from_bytes(&source_bytes, &doc_key, None)
        .with_context(|| format!("load source {}", target.doc_guid))?;
    let current_doc = load_doc_from_bytes(&current_bytes, &doc_key, None)
        .with_context(|| format!("load current {}", target.doc_guid))?;
    let selection = select_source_roots(&source_doc, only, except)?;
    print_root_selection(&selection);
    ensure_selection_can_run(&selection, "verify")?;
    let roots = &selection.map_roots;

    let source_entries = collect_source_entries(&source_doc, roots)?;
    let current_entries = collect_source_entries(&current_doc, roots)?;
    let owners = live_key_owners(&source_doc, roots)?;
    let (client_groups, _) = group_entries_by_client(&source_doc, &source_entries, &owners)?;

    let source_counts = root_counts(&source_doc, roots);
    let current_counts = root_counts(&current_doc, roots);
    let source_sv = state_vector(&source_doc);
    let current_sv = state_vector(&current_doc);
    let versions = store.list_versions(&storage_key).await.unwrap_or_default();
    let latest = versions
        .iter()
        .find(|version| version.is_latest)
        .or_else(|| versions.first());

    let counts_ok = source_counts == current_counts;
    let entries_ok = source_entries == current_entries;
    let clocks_ok = client_groups
        .keys()
        .all(|client_id| current_sv.get(client_id) > source_sv.get(client_id));
    println!(
        "{} counts_ok={} entries_ok={} clocks_advanced={} current {} latest={}",
        target.doc_guid,
        counts_ok,
        entries_ok,
        clocks_ok,
        format_counts(&current_counts),
        latest
            .map(|version| version.version_id.as_str())
            .unwrap_or("<unknown>")
    );
    for (client_id, keys) in client_groups {
        println!(
            "  client {} keys={} {} clock {} -> {}",
            client_id,
            keys.len(),
            format_key_counts(&keys),
            source_sv.get(&client_id),
            current_sv.get(&client_id)
        );
    }

    if !counts_ok || !entries_ok || !clocks_ok {
        bail!("verification failed for {}", target.doc_guid);
    }

    Ok(())
}

async fn repair_one(
    store: Arc<Box<dyn Store>>,
    relay_guid: &str,
    target: &RestoreTarget,
    only: &BTreeSet<String>,
    except: &BTreeSet<String>,
    write: bool,
) -> Result<()> {
    let doc_key = format!("{}-{}", relay_guid, target.doc_guid);
    let storage_key = format!("{}/data.ysweet", doc_key);
    let source_bytes = store
        .get_version(&storage_key, &target.version_id)
        .await?
        .with_context(|| format!("missing version {} for {}", target.version_id, storage_key))?;
    let source_doc = load_doc_from_bytes(&source_bytes, &doc_key, None)
        .with_context(|| format!("load source {}", target.doc_guid))?;
    let selection = select_source_roots(&source_doc, only, except)?;
    print_root_selection(&selection);
    if write {
        ensure_selection_can_run(&selection, "write")?;
    }
    if selection.map_roots.is_empty() {
        return Ok(());
    }
    let roots = &selection.map_roots;

    let source_entries = collect_source_entries(&source_doc, roots)?;
    let owners = live_key_owners(&source_doc, roots)?;
    let (client_groups, missing_owners) =
        group_entries_by_client(&source_doc, &source_entries, &owners)?;

    let source_counts = root_counts(&source_doc, roots);

    println!(
        "{} source {} clients={} missing_owner={}",
        target.doc_guid,
        format_counts(&source_counts),
        client_groups.len(),
        missing_owners
    );
    for (client_id, keys) in &client_groups {
        println!("  client {} {}", client_id, format_key_counts(keys));
    }

    if !write {
        return Ok(());
    }

    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=5 {
        match write_repair_attempt(store.clone(), &doc_key, &source_entries, &client_groups).await {
            Ok(counts) => {
                println!(
                    "  wrote attempt={} current {}",
                    attempt,
                    format_counts(&counts)
                );
                return Ok(());
            }
            Err(err) if is_lease_conflict(&err) => {
                println!("  lease conflict on attempt={}, retrying", attempt);
                last_err = Some(err);
            }
            Err(err) => return Err(err),
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("repair failed without an error")))
}

fn group_entries_by_client(
    source_doc: &Doc,
    source_entries: &BTreeMap<RootKey, Any>,
    owners: &HashMap<RootKey, u64>,
) -> Result<(BTreeMap<u64, Vec<RootKey>>, usize)> {
    let fallback_client = if source_entries.is_empty() {
        None
    } else {
        Some(fallback_client_id(source_doc)?)
    };
    let mut missing_owners = 0;
    let mut client_groups: BTreeMap<u64, Vec<RootKey>> = BTreeMap::new();

    for root_key in source_entries.keys() {
        let client_id = match owners.get(root_key).copied() {
            Some(client_id) => client_id,
            None => {
                missing_owners += 1;
                fallback_client.expect("source entries require a fallback client")
            }
        };
        client_groups
            .entry(client_id)
            .or_default()
            .push(root_key.clone());
    }

    Ok((client_groups, missing_owners))
}

async fn write_repair_attempt(
    store: Arc<Box<dyn Store>>,
    doc_key: &str,
    source_entries: &BTreeMap<RootKey, Any>,
    client_groups: &BTreeMap<u64, Vec<RootKey>>,
) -> Result<RootCounts> {
    let sync_kv = Arc::new(SyncKv::new(Some(store), doc_key, || ()).await?);
    let main_doc = load_doc_from_sync_kv(&sync_kv, None)?;
    let roots = source_entries
        .keys()
        .map(|key| key.root.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let sync_for_observer = sync_kv.clone();
    let _subscription = main_doc.observe_update_v1(move |_, event| {
        sync_for_observer
            .push_update(DOC_NAME, &event.update)
            .expect("push repair update");
        sync_for_observer
            .flush_doc_with(DOC_NAME, Default::default())
            .expect("flush repair update");
    });

    for (&client_id, root_keys) in client_groups {
        let update = build_client_update(&main_doc, client_id, root_keys, source_entries)
            .with_context(|| format!("build update for client {}", client_id))?;
        if update.is_empty() {
            continue;
        }
        let update = Update::decode_v1(&update)
            .map_err(|err| anyhow::anyhow!("decode generated update: {}", err))?;
        let mut txn = main_doc.transact_mut();
        txn.apply_update(update);
    }

    persist_with_anyhow(&sync_kv).await?;
    Ok(root_counts(&main_doc, &roots))
}

fn build_client_update(
    base_doc: &Doc,
    client_id: u64,
    root_keys: &[RootKey],
    source_entries: &BTreeMap<RootKey, Any>,
) -> Result<Vec<u8>> {
    let full_update = {
        let txn = base_doc.transact();
        txn.encode_state_as_update_v1(&StateVector::default())
    };

    let temp_doc = Doc::with_client_id(client_id);
    {
        let update = Update::decode_v1(&full_update)
            .map_err(|err| anyhow::anyhow!("decode base update: {}", err))?;
        let mut txn = temp_doc.transact_mut();
        txn.apply_update(update);
    }

    let before = {
        let txn = temp_doc.transact();
        txn.state_vector()
    };

    let root_names = root_keys
        .iter()
        .map(|root_key| root_key.root.clone())
        .collect::<BTreeSet<_>>();
    let map_handles = root_names
        .iter()
        .map(|root| (root.clone(), temp_doc.get_or_insert_map(root.as_str())))
        .collect::<HashMap<_, _>>();
    {
        let mut txn = temp_doc.transact_mut();
        for root_key in root_keys {
            let map = map_handles
                .get(&root_key.root)
                .with_context(|| format!("missing root map handle for {}", root_key.root))?;
            map.remove(&mut txn, root_key.key.as_str());
            let value = source_entries
                .get(root_key)
                .with_context(|| format!("missing source value for {:?}", root_key))?
                .clone();
            map.insert(&mut txn, root_key.key.clone(), In::from(value));
        }
    }

    let txn = temp_doc.transact();
    Ok(txn.encode_diff_v1(&before))
}

fn load_doc_from_bytes(bytes: &[u8], doc_key: &str, client_id: Option<u64>) -> Result<Doc> {
    let (sync_kv, _) = SyncKv::from_bytes(bytes, doc_key)?;
    load_doc_from_sync_kv(&sync_kv, client_id)
}

fn load_doc_from_sync_kv(sync_kv: &SyncKv, client_id: Option<u64>) -> Result<Doc> {
    let doc = client_id.map(Doc::with_client_id).unwrap_or_else(Doc::new);
    let mut txn = doc.transact_mut();
    sync_kv
        .load_doc(DOC_NAME, &mut txn)
        .map_err(|err| anyhow::anyhow!("load yrs doc from SyncKv: {}", err))?;
    drop(txn);
    Ok(doc)
}

fn collect_source_entries(doc: &Doc, roots: &[String]) -> Result<BTreeMap<RootKey, Any>> {
    let mut entries = BTreeMap::new();
    for root in roots {
        let map = doc.get_or_insert_map(root.as_str());
        let txn = doc.transact();
        for (key, out) in map.iter(&txn) {
            let value = match out {
                Out::Any(any) => any,
                other => bail!("unexpected {} value for {}: {:?}", root, key, other),
            };
            entries.insert(
                RootKey {
                    root: root.clone(),
                    key: key.to_string(),
                },
                value,
            );
        }
    }
    Ok(entries)
}

fn live_key_owners(doc: &Doc, roots: &[String]) -> Result<HashMap<RootKey, u64>> {
    let root_filter = roots.iter().map(String::as_str).collect::<HashSet<_>>();
    let txn = doc.transact();
    let full_update = txn.encode_state_as_update_v1(&StateVector::default());
    let snapshot = txn.snapshot();
    let mut deleted_ranges: HashMap<u64, Vec<(u32, u32)>> = HashMap::new();
    for (&client_id, ranges) in snapshot.delete_set.iter() {
        deleted_ranges.insert(
            client_id,
            ranges
                .iter()
                .map(|range| (range.start, range.end))
                .collect(),
        );
    }
    drop(txn);

    let mut owners = HashMap::new();
    for item in decode_v1_item_parents(&full_update).map_err(|err| anyhow::anyhow!(err))? {
        let Some(root) = item.parent_named.as_deref() else {
            continue;
        };
        let Some(parent_sub) = item.parent_sub else {
            continue;
        };
        if !root_filter.contains(root) {
            continue;
        }
        if item_is_deleted(&deleted_ranges, item.client, item.clock, item.len) {
            continue;
        }
        owners.insert(
            RootKey {
                root: root.to_string(),
                key: parent_sub,
            },
            item.client,
        );
    }

    Ok(owners)
}

fn item_is_deleted(
    deleted_ranges: &HashMap<u64, Vec<(u32, u32)>>,
    client_id: u64,
    clock: u32,
    len: u32,
) -> bool {
    let Some(ranges) = deleted_ranges.get(&client_id) else {
        return false;
    };
    let end = clock.saturating_add(len);
    ranges
        .iter()
        .any(|(start, range_end)| *start <= clock && end <= *range_end)
}

fn fallback_client_id(doc: &Doc) -> Result<u64> {
    let txn = doc.transact();
    txn.state_vector()
        .iter()
        .max_by_key(|(_, &clock)| clock)
        .map(|(&client_id, _)| client_id)
        .context("source document has no client IDs")
}

fn state_vector(doc: &Doc) -> StateVector {
    let txn = doc.transact();
    txn.state_vector()
}

type RootCounts = BTreeMap<String, u32>;

fn root_counts(doc: &Doc, roots: &[String]) -> RootCounts {
    let map_handles = roots
        .iter()
        .map(|root| (root.clone(), doc.get_or_insert_map(root.as_str())))
        .collect::<Vec<_>>();
    let txn = doc.transact();
    map_handles
        .into_iter()
        .map(|(root, map)| (root, map.len(&txn)))
        .collect()
}

fn format_counts(counts: &RootCounts) -> String {
    counts
        .iter()
        .map(|(root, count)| format!("{}={}", root, count))
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_key_counts(keys: &[RootKey]) -> String {
    let mut counts = BTreeMap::new();
    for key in keys {
        *counts.entry(key.root.clone()).or_insert(0usize) += 1;
    }
    counts
        .iter()
        .map(|(root, count)| format!("{}={}", root, count))
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_lease_conflict(err: &anyhow::Error) -> bool {
    if err.downcast_ref::<RepairLeaseConflict>().is_some() {
        return true;
    }
    for cause in err.chain() {
        if let Some(StoreError::LeaseConflict(_)) = cause.downcast_ref::<StoreError>() {
            return true;
        }
    }
    false
}

async fn persist_with_anyhow(sync_kv: &SyncKv) -> Result<()> {
    match sync_kv.persist_if_unchanged().await {
        Ok(()) => Ok(()),
        Err(err) => {
            if let Some(StoreError::LeaseConflict(message)) = err.downcast_ref::<StoreError>() {
                Err(RepairLeaseConflict(message.clone()).into())
            } else {
                Err(anyhow::anyhow!("persist repair snapshot: {}", err))
            }
        }
    }
}

#[derive(Debug)]
struct RepairLeaseConflict(String);

impl std::fmt::Display for RepairLeaseConflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "lease conflict: {}", self.0)
    }
}

impl std::error::Error for RepairLeaseConflict {}

#[derive(Debug)]
struct DecodedItemMeta {
    client: u64,
    clock: u32,
    len: u32,
    parent_named: Option<String>,
    parent_sub: Option<String>,
}

fn decode_v1_item_parents(bytes: &[u8]) -> std::result::Result<Vec<DecodedItemMeta>, String> {
    use lib0::decoding::{Cursor, Read};

    let mut cursor = Cursor::new(bytes);
    let mut items = Vec::new();

    let num_clients: u32 = cursor
        .read_var()
        .map_err(|err| format!("num_clients: {:?}", err))?;
    for _ in 0..num_clients {
        let num_blocks: u32 = cursor
            .read_var()
            .map_err(|err| format!("num_blocks: {:?}", err))?;
        let client: u32 = cursor
            .read_var()
            .map_err(|err| format!("client: {:?}", err))?;
        let mut clock: u32 = cursor
            .read_var()
            .map_err(|err| format!("clock: {:?}", err))?;

        for block_idx in 0..num_blocks {
            let info = cursor.read_u8().map_err(|err| format!("info: {:?}", err))?;
            let content_ref = info & 0x0f;

            if content_ref == 10 {
                let len: u32 = cursor
                    .read_var()
                    .map_err(|err| format!("skip len: {:?}", err))?;
                clock += len;
                continue;
            }
            if content_ref == 0 {
                let len: u32 = cursor
                    .read_var()
                    .map_err(|err| format!("gc len: {:?}", err))?;
                clock += len;
                continue;
            }

            let has_origin = info & 0x80 != 0;
            let has_right_origin = info & 0x40 != 0;
            let cant_copy_parent = !has_origin && !has_right_origin;

            if has_origin {
                let _: u32 = cursor
                    .read_var()
                    .map_err(|err| format!("origin client: {:?}", err))?;
                let _: u32 = cursor
                    .read_var()
                    .map_err(|err| format!("origin clock: {:?}", err))?;
            }

            if has_right_origin {
                let _: u32 = cursor
                    .read_var()
                    .map_err(|err| format!("right client: {:?}", err))?;
                let _: u32 = cursor
                    .read_var()
                    .map_err(|err| format!("right clock: {:?}", err))?;
            }

            let mut parent_named = None;
            if cant_copy_parent {
                let parent_info: u32 = cursor
                    .read_var()
                    .map_err(|err| format!("parent_info: {:?}", err))?;
                if parent_info == 1 {
                    let name = cursor
                        .read_string()
                        .map_err(|err| format!("parent name: {:?}", err))?;
                    parent_named = Some(name.to_string());
                } else {
                    let _: u32 = cursor
                        .read_var()
                        .map_err(|err| format!("parent id client: {:?}", err))?;
                    let _: u32 = cursor
                        .read_var()
                        .map_err(|err| format!("parent id clock: {:?}", err))?;
                }
            }

            let parent_sub = if cant_copy_parent && (info & 0x20 != 0) {
                let value = cursor
                    .read_string()
                    .map_err(|err| format!("parent_sub: {:?}", err))?;
                Some(value.to_string())
            } else {
                None
            };

            let content_len = skip_v1_content(&mut cursor, content_ref).map_err(|err| {
                format!(
                    "content skip at client={} clock={} block={} ref={}: {}",
                    client, clock, block_idx, content_ref, err
                )
            })?;

            items.push(DecodedItemMeta {
                client: client as u64,
                clock,
                len: content_len,
                parent_named,
                parent_sub,
            });

            clock += content_len;
        }
    }

    Ok(items)
}

fn skip_v1_content(
    cursor: &mut lib0::decoding::Cursor,
    content_ref: u8,
) -> std::result::Result<u32, String> {
    use lib0::decoding::Read;

    match content_ref {
        1 => {
            let len: u32 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
            Ok(len)
        }
        2 => {
            let count: u32 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
            for _ in 0..=count {
                cursor.read_buf().map_err(|err| format!("{:?}", err))?;
            }
            Ok(count + 1)
        }
        3 => {
            cursor.read_buf().map_err(|err| format!("{:?}", err))?;
            Ok(1)
        }
        4 => {
            let buf = cursor.read_buf().map_err(|err| format!("{:?}", err))?;
            Ok(buf.len() as u32)
        }
        5 => {
            cursor.read_buf().map_err(|err| format!("{:?}", err))?;
            Ok(1)
        }
        6 => {
            cursor.read_buf().map_err(|err| format!("{:?}", err))?;
            cursor.read_buf().map_err(|err| format!("{:?}", err))?;
            Ok(1)
        }
        7 => {
            let type_ref = cursor.read_u8().map_err(|err| format!("{:?}", err))?;
            if matches!(type_ref, 3 | 5) {
                cursor.read_buf().map_err(|err| format!("{:?}", err))?;
            }
            Ok(1)
        }
        8 => {
            let count: u32 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
            for _ in 0..count {
                skip_any_value(cursor)?;
            }
            Ok(count.max(1))
        }
        9 => {
            cursor.read_buf().map_err(|err| format!("{:?}", err))?;
            skip_any_value(cursor)?;
            Ok(1)
        }
        11 => {
            let flags: i64 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
            let is_collapsed = (flags & 1) != 0;
            let _: u64 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
            let _: u32 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
            if !is_collapsed {
                let _: u64 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
                let _: u32 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
            }
            Ok(1)
        }
        other => Err(format!("unknown content ref: {}", other)),
    }
}

fn skip_any_value(cursor: &mut lib0::decoding::Cursor) -> std::result::Result<(), String> {
    use lib0::decoding::Read;

    let tag = cursor.read_u8().map_err(|err| format!("{:?}", err))?;
    match tag {
        127 | 126 | 121 | 120 => {}
        125 => {
            let _: i64 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
        }
        124 => {
            cursor.read_exact(4).map_err(|err| format!("{:?}", err))?;
        }
        123 => {
            cursor.read_exact(8).map_err(|err| format!("{:?}", err))?;
        }
        122 => {
            cursor.read_exact(8).map_err(|err| format!("{:?}", err))?;
        }
        119 => {
            cursor.read_buf().map_err(|err| format!("{:?}", err))?;
        }
        118 => {
            let len: u32 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
            for _ in 0..len {
                cursor.read_buf().map_err(|err| format!("{:?}", err))?;
                skip_any_value(cursor)?;
            }
        }
        117 => {
            let len: u32 = cursor.read_var().map_err(|err| format!("{:?}", err))?;
            for _ in 0..len {
                skip_any_value(cursor)?;
            }
        }
        116 => {
            cursor.read_buf().map_err(|err| format!("{:?}", err))?;
        }
        other => return Err(format!("unknown Any tag: {}", other)),
    }
    Ok(())
}
