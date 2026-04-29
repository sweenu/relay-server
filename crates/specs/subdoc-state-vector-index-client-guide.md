# Client Implementor's Guide: Subdocument Snapshot Index

## Overview

The subdocument snapshot index allows a client connected to a **parent document** to efficiently determine which known subdocuments have changed since its last connection, without opening a sync connection to every known subdocument.

This guide covers how to implement the client side in TypeScript, building on the existing `YSweetProvider` pattern in `~/stash/relay/src/client/provider.ts`.

## New Message Types

Two new sync protocol message types are added:

```typescript
// provider.ts — add alongside existing constants
export const messageQuerySubdocs = 7
export const messageSubdocs = 8
```

These follow the same pattern as the existing message type constants (`messageSync = 0`, `messageAwareness = 1`, etc.).

### `MSG_QUERY_SUBDOCS` (7) — Client → Server

Payload is a varuint GUID count followed by that many varstring GUIDs. The count must be between `1` and `100`, inclusive. There is no broad "all subdocuments" query; clients send explicit batches from their known GUID set.

### `MSG_SUBDOCS` (8) — Server → Client

Payload is a CBOR envelope with a `data` map. Keys are subdocument ID strings; values include raw Yjs snapshot bytes and the server timestamp for the edit that produced that snapshot:

```
{
  "data": {
    "subdoc-abc": {
      "snapshot": <Uint8Array of encoded snapshot>,
      "last_seen": 1710000000000,
    },
    "subdoc-def": {
      "snapshot": <Uint8Array of encoded snapshot>,
      "last_seen": 1710000000100,
    },
  },
}
```

## Wire Format

Both message types use the standard lib0 varint encoding, matching every other message in the protocol.

### Sending `MSG_QUERY_SUBDOCS`

```typescript
import * as encoding from 'lib0/encoding'

export const maxSubdocQueryBatchSize = 100

function sendQuerySubdocs(ws: WebSocket, guids: string[]) {
  if (guids.length === 0) {
    throw new Error('MSG_QUERY_SUBDOCS requires at least one GUID')
  }
  if (guids.length > maxSubdocQueryBatchSize) {
    throw new Error(`MSG_QUERY_SUBDOCS accepts at most ${maxSubdocQueryBatchSize} GUIDs`)
  }

  const encoder = encoding.createEncoder()
  encoding.writeVarUint(encoder, 7) // messageQuerySubdocs
  encoding.writeVarUint(encoder, guids.length)
  guids.forEach(guid => {
    encoding.writeVarString(encoder, guid)
  })
  ws.send(encoding.toUint8Array(encoder))
}

function sendQuerySubdocBatches(ws: WebSocket, guids: string[]) {
  for (let i = 0; i < guids.length; i += maxSubdocQueryBatchSize) {
    sendQuerySubdocs(ws, guids.slice(i, i + maxSubdocQueryBatchSize))
  }
}
```

Request batching is client-side over the known GUID set. A zero-count query is invalid, and a request larger than `100` GUIDs is invalid.

### Receiving `MSG_SUBDOCS`

The response handler reads a length-prefixed CBOR buffer, then decodes it:

```typescript
import * as decoding from 'lib0/decoding'
import { decode as decodeCBOR } from 'cbor-x'

type SubdocSnapshotEntry = {
  snapshot: Uint8Array
  last_seen: number
}

type SubdocSnapshotEnvelope = {
  data?: Record<string, SubdocSnapshotEntry>
}

// Register in the messageHandlers array at index 8
messageHandlers[messageSubdocs] = (
  _encoder,
  decoder,
  provider,
  _emitSynced,
  _messageType,
) => {
  // Read the CBOR payload (same framing as messageEvent)
  const cborLength = decoding.readVarUint(decoder)
  const cborData = decoding.readUint8Array(decoder, cborLength)

  try {
    const envelope: SubdocSnapshotEnvelope = decodeCBOR(cborData)
    provider.handleSubdocIndex(envelope.data ?? {})
  } catch (error) {
    console.error('Failed to decode subdoc snapshot index:', error)
  }
}
```

The decoded object contains a `data` map. Each entry has a Yjs snapshot encoded with `Y.encodeSnapshot(Y.snapshot(doc))` and a `last_seen` timestamp. The timestamp identifies the server-side edit time for the returned snapshot; it is not the time at which this query was served. A snapshot includes both the state vector and delete set.

## Integration into YSweetProvider

### When to Send the Query

Send `MSG_QUERY_SUBDOCS` after the initial sync handshake completes — specifically, after `synced` becomes `true`. This is the same point at which the existing code re-subscribes to events.

The natural place is inside `websocket.onopen` in `setupWS`, right after flushing pending messages and re-subscribing to events:

```typescript
// In setupWS, inside websocket.onopen, after event re-subscription:

// Query subdoc snapshots for catch-up, in explicit GUID batches
if (provider.onSubdocIndex && provider.knownSubdocGuids.length > 0) {
  sendQuerySubdocBatches(websocket, provider.knownSubdocGuids)
}
```

Alternatively, send it from a `once('synced', ...)` handler if you want to wait until the parent document itself is fully synced before performing subdoc catch-up.

### Handling the Response

Add a method to `YSweetProvider`:

```typescript
export type SubdocIndexCallback = (
  staleDocIds: string[],
  returnedDocIds: string[],
) => void

// In YSweetProvider class:

onSubdocIndex: SubdocIndexCallback | null = null
knownSubdocGuids: string[] = []

/** Map of local snapshots by doc ID, populated by the consumer */
localSnapshots: Map<string, Uint8Array> = new Map()

handleSubdocIndex(serverIndex: Record<string, SubdocSnapshotEntry>) {
  const returnedDocIds = Object.keys(serverIndex)
  const staleDocIds: string[] = []

  for (const [docId, serverEntry] of Object.entries(serverIndex)) {
    const serverSnapshot = serverEntry.snapshot
    const localSnapshot = this.localSnapshots.get(docId)

    if (!localSnapshot) {
      // Never seen this doc — it's stale (or new)
      staleDocIds.push(docId)
      continue
    }

    if (!snapshotsEqual(localSnapshot, serverSnapshot)) {
      staleDocIds.push(docId)
    }
  }

  this.onSubdocIndex?.(staleDocIds, returnedDocIds)
}
```

### Snapshot Comparison

Yjs snapshots include both a state vector and a delete set. Two subdocuments are caught up only when both parts match. The comparison function:

```typescript
import * as Y from 'yjs'

function snapshotsEqual(a: Uint8Array, b: Uint8Array): boolean {
  // Fast path: byte-level equality
  if (a.length === b.length) {
    let equal = true
    for (let i = 0; i < a.length; i++) {
      if (a[i] !== b[i]) {
        equal = false
        break
      }
    }
    if (equal) return true
  }

  return Y.equalSnapshots(Y.decodeSnapshot(a), Y.decodeSnapshot(b))
}
```

### Getting Local Snapshots

The consumer must populate `localSnapshots` before the query is sent. How you get them depends on your storage layer:

```typescript
// Example: reading snapshots from IndexedDB-persisted Y.Docs
async function getLocalSnapshots(
  docIds: string[],
): Promise<Map<string, Uint8Array>> {
  const result = new Map<string, Uint8Array>()

  for (const docId of docIds) {
    const doc = await loadDocFromIDB(docId) // your persistence layer
    if (doc) {
      result.set(docId, Y.encodeSnapshot(Y.snapshot(doc)))
      doc.destroy()
    }
  }

  return result
}
```

If you don't have any local snapshots (first connection), every returned subdocument will appear stale — which is correct. The client still needs a known GUID list from the parent document or its own file index before it can query snapshots.

## End-to-End Flow

Here's the complete reconnection catch-up sequence:

```
                     Client                          Server
                       │                               │
  1. Connect WS        │─── WebSocket connect ────────>│
                       │                               │
  2. Sync handshake    │<── SyncStep1 (server SV) ─────│
                       │─── SyncStep2 (client update) ─>│
                       │<── SyncStep2 (server update) ──│
                       │                               │
  3. Synced            │  (provider.synced = true)      │
                       │                               │
  4. Query subdocs     │─── MSG_QUERY_SUBDOCS (7) ────>│
                       │    up to 100 explicit GUIDs   │
                       │                               │
  5. Receive index     │<── MSG_SUBDOCS (8) ───────────│
                       │    {data: {docId: {...}}}      │
                       │                               │
  6. Compare locally   │  for each (docId, serverSnap): │
                       │    if localSnap != serverSnap: │
                       │      staleDocIds.push(docId)   │
                       │                               │
  7. Sync stale docs   │─── open WS to subdoc-abc ────>│
                       │─── open WS to subdoc-def ────>│
                       │    (only the stale ones)       │
                       │                               │
  8. Subscribe events  │─── MSG_EVENT_SUBSCRIBE ──────>│
                       │    ["document.updated"]        │
                       │                               │
  9. Ongoing updates   │<── MSG_EVENT (4) ─────────────│
                       │    (real-time from here on)    │
```

Steps 4-6 repeat once per GUID batch and replace the naive approach of opening a sync connection to every known subdocument.

## Integration Example: SharedFolder

In `SharedFolder.ts`, the existing `setupEventSubscriptions()` subscribes to `"document.updated"` for real-time updates. The subdoc index adds a catch-up step before that:

```typescript
// In SharedFolder, after provider is created and synced:

private async performSubdocCatchUp() {
  if (!this._provider) return

  // Collect local snapshots for all known documents
  const docIds: string[] = []
  const localSnapshots = new Map<string, Uint8Array>()
  for (const [guid, file] of this.files) {
    if (isDocument(file)) {
      const docId = `${this.relayId}-${guid}`
      docIds.push(docId)
      const doc = await this.loadDocFromStorage(guid)
      if (doc) {
        localSnapshots.set(docId, Y.encodeSnapshot(Y.snapshot(doc)))
        doc.destroy()
      }
    }
  }

  this._provider.localSnapshots = localSnapshots
  this._provider.knownSubdocGuids = docIds
  this._provider.onSubdocIndex = (staleDocIds, _returnedDocIds) => {
    // Sync only the stale documents
    for (const docId of staleDocIds) {
      this.syncDocument(docId)
    }
  }

  // Send the query (if already connected; otherwise it fires on next connect)
  if (this._provider.wsconnected && docIds.length > 0) {
    sendQuerySubdocBatches(this._provider.ws!, docIds)
  }
}
```

## Edge Cases

### First Connection (No Local State)

If the client has no local snapshots (fresh install), every returned subdocument appears stale. This is correct — the client needs to sync the documents it knows about locally or from the parent document.

### Unknown or Deleted GUIDs

If none of the requested GUIDs exist in the server's index, the server returns `{ data: {} }`. The callback receives `staleDocIds = []` and `returnedDocIds = []` for that request.

### Empty Query

The client must not send a zero-count query. `MSG_QUERY_SUBDOCS` requires at least one GUID.

### Oversized Query

The client must split larger query sets into batches of at most `100` GUIDs. The server rejects larger requests instead of truncating them.

### Race: Updates During Catch-Up

If subdocuments are updated while the client is syncing stale ones, those updates are handled by the normal Yjs sync protocol on each subdocument's own WebSocket connection. Once the client subscribes to `document.updated` events on the parent, it receives real-time notifications for any further changes. The brief window between receiving the index and subscribing to events is safe because each individual subdoc sync uses the Yjs state exchange, which is idempotent.

### Invalid Frames

A tag-only `MSG_QUERY_SUBDOCS` frame is invalid. The client must always write a non-zero GUID count after message type 7, followed by exactly that many GUID strings.

## Dependencies

The implementation uses the same dependencies already in the project:

- **lib0** (`encoding`, `decoding`) — message framing
- **cbor-x** (`decode`) — CBOR deserialization of the subdoc index
- **yjs** (`Y.snapshot`, `Y.encodeSnapshot`, `Y.decodeSnapshot`, `Y.equalSnapshots`) — snapshot operations
