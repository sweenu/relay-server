//! One-shot data migrations applied to the configured store.
//!
//! Each migration has a stable ID and a completion marker stored at
//! `.migrations/<id>.complete` in the store. On run, migrations whose
//! marker already exists are skipped. On success, the marker is written.
//! Migrations must be idempotent: a crash mid-run will leave no marker,
//! and the next run will re-execute the whole migration.
//!
//! This is intentionally a thin wrapper, not a framework. When a second
//! migration is added, the abstraction can grow with the actual second
//! use case.
//!
//! Currently registered:
//! - `0001-subdocs-index` — bucket-wide subdocs snapshot index backfill.

use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use y_sweet_core::store::Store;

use crate::subdocs;

const MARKER_PREFIX: &str = ".migrations/";

type MigrationFn = fn(
    Arc<Box<dyn Store>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>>;

/// All registered migrations, in run order.
fn registered() -> Vec<(&'static str, MigrationFn)> {
    vec![("0001-subdocs-index", migration_0001_subdocs_index)]
}

/// Check completion markers and run any migrations that haven't been
/// applied yet. Stops on the first failure.
pub async fn run_pending(store: Arc<Box<dyn Store>>) -> Result<()> {
    store
        .init()
        .await
        .context("store init failed before running migrations")?;

    for (id, run) in registered() {
        let marker = marker_key(id);
        if marker_exists(store.as_ref().as_ref(), &marker).await? {
            tracing::info!(migration = id, "Skipping migration (already applied)");
            continue;
        }
        tracing::info!(migration = id, "Running migration");
        run(store.clone())
            .await
            .with_context(|| format!("migration {} failed", id))?;
        write_marker(store.as_ref().as_ref(), &marker)
            .await
            .with_context(|| format!("failed to write completion marker for {}", id))?;
        tracing::info!(migration = id, "Migration complete");
    }
    Ok(())
}

fn marker_key(id: &str) -> String {
    format!("{}{}.complete", MARKER_PREFIX, id)
}

async fn marker_exists(store: &dyn Store, key: &str) -> Result<bool> {
    Ok(store.exists(key).await?)
}

async fn write_marker(store: &dyn Store, key: &str) -> Result<()> {
    let body = current_timestamp_iso8601().into_bytes();
    store.set(key, body).await?;
    Ok(())
}

fn current_timestamp_iso8601() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Plain seconds-since-epoch as a debug-friendly body; the marker's
    // existence is what matters, not its contents.
    format!("applied_at_unix_seconds={}\n", now)
}

fn migration_0001_subdocs_index(
    store: Arc<Box<dyn Store>>,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send>> {
    Box::pin(async move {
        let mut continuation_token: Option<String> = None;
        let mut pages = 0usize;
        let mut candidate_count = 0usize;
        let mut folder_count = 0usize;
        let mut errors = 0usize;

        loop {
            let page = store
                .list_directory_page("", continuation_token.as_deref())
                .await
                .context("failed to list store contents")?;
            pages += 1;

            // Discover docs by matching `*/data.ysweet` keys, then split the
            // doc_id into (relay_id, doc_guid). Skip anything that doesn't match
            // the standard `<uuid>-<uuid>` layout.
            let doc_ids = page
                .common_prefixes
                .into_iter()
                .filter_map(doc_id_from_common_prefix)
                .chain(
                    page.files
                        .into_iter()
                        .filter_map(|info| {
                            info.key.strip_suffix("/data.ysweet").map(str::to_string)
                        })
                        .filter(|doc_id| !doc_id.contains('/')),
                )
                .collect::<Vec<_>>();

            for doc_id in doc_ids {
                let Some((relay_id, doc_guid)) = parse_doc_id(&doc_id) else {
                    tracing::warn!(doc_id = doc_id.as_str(), "Skipping non-UUID-shaped doc_id");
                    continue;
                };

                candidate_count += 1;
                // Each backfill call loads the doc, checks for `filemeta_v0`,
                // and no-ops if the root is absent.
                match subdocs::run_backfill(store.clone(), &relay_id, &doc_guid, false, false).await
                {
                    Ok(()) => {
                        folder_count += 1;
                    }
                    Err(e) => {
                        errors += 1;
                        tracing::error!(
                            relay_id = relay_id.as_str(),
                            doc_guid = doc_guid.as_str(),
                            error = %e,
                            "Backfill failed for doc",
                        );
                    }
                }
            }

            tracing::info!(
                page = pages,
                candidates = candidate_count,
                processed = folder_count,
                errors,
                "Subdocs index migration progress"
            );

            let Some(next_token) = page.next_continuation_token else {
                break;
            };
            continuation_token = Some(next_token);
        }

        if errors > 0 {
            anyhow::bail!(
                "subdocs index migration finished with {} errors across {} candidate docs",
                errors,
                candidate_count
            );
        }
        tracing::info!(
            processed = folder_count,
            total = candidate_count,
            pages,
            "subdocs index migration done"
        );
        Ok(())
    })
}

/// Parse `<uuid>-<uuid>` into (relay_id, doc_guid). UUIDs are 36 chars
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`); the full doc_id is 73 chars
/// with the boundary at position 36.
fn parse_doc_id(s: &str) -> Option<(String, String)> {
    if s.len() != 73 {
        return None;
    }
    let bytes = s.as_bytes();
    if bytes[36] != b'-' {
        return None;
    }
    let relay = &s[..36];
    let doc = &s[37..];
    if !is_uuid_shape(relay) || !is_uuid_shape(doc) {
        return None;
    }
    Some((relay.to_string(), doc.to_string()))
}

fn doc_id_from_common_prefix(prefix: String) -> Option<String> {
    let doc_id = prefix.trim_end_matches('/');
    if doc_id.is_empty()
        || doc_id.contains('/')
        || doc_id == "files"
        || doc_id.starts_with('.')
        || doc_id.starts_with(MARKER_PREFIX.trim_end_matches('/'))
    {
        return None;
    }
    Some(doc_id.to_string())
}

fn is_uuid_shape(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        let expected_hyphen = matches!(i, 8 | 13 | 18 | 23);
        if expected_hyphen {
            if *b != b'-' {
                return false;
            }
        } else if !b.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_uuid_pair() {
        let s = "11111111-2222-3333-4444-555555555555-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        let (relay, doc) = parse_doc_id(s).expect("should parse");
        assert_eq!(relay, "11111111-2222-3333-4444-555555555555");
        assert_eq!(doc, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(parse_doc_id("short").is_none());
    }

    #[test]
    fn rejects_non_hex() {
        let s = "ZZZZZZZZ-2222-3333-4444-555555555555-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
        assert!(parse_doc_id(s).is_none());
    }

    #[test]
    fn rejects_missing_separator() {
        let mut s = String::from(
            "11111111-2222-3333-4444-5555555555550aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        );
        // length right (73), but byte at 36 is '0' instead of '-'
        assert_eq!(s.len(), 73);
        // sanity
        let bytes = unsafe { s.as_bytes_mut() };
        assert_eq!(bytes[36], b'0');
        assert!(parse_doc_id(&s).is_none());
    }
}
