# Client Implementor's Guide: Subdocument Snapshot Index

## Overview

The subdocument snapshot index allows a client connected to a **parent document** to efficiently determine which subdocuments have changed since its last connection, without opening a sync connection to every subdocument.

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

Payload is a varuint GUID count followed by that many varstring GUIDs. Send count `0` to request the full subdocument snapshot index from the server.

### `MSG_SUBDOCS` (8) — Server → Client

Payload is a CBOR map where keys are subdocument ID strings and values are raw Yjs snapshot bytes:

```
{
  "subdoc-abc": <Uint8Array of encoded snapshot>,
  "subdoc-def": <Uint8Array of encoded snapshot>,
}
```

## Wire Format

Both message types use the standard lib0 varint encoding, matching every other message in the protocol.

### Sending `MSG_QUERY_SUBDOCS`

```typescript
import * as encoding from 'lib0/encoding'

function sendQuerySubdocs(ws: WebSocket, guids: string[] = []) {
  const encoder = encoding.createEncoder()
  encoding.writeVarUint(encoder, 7) // messageQuerySubdocs
  encoding.writeVarUint(encoder, guids.length)
  guids.forEach(guid => {
    encoding.writeVarString(encoder, guid)
  })
  ws.send(encoding.toUint8Array(encoder))
}
```

For "all subdocs", `guids` is empty and the wire bytes are `0x07 0x00`: message type 7 followed by a zero count.

### Receiving `MSG_SUBDOCS`

The response handler reads a length-prefixed CBOR buffer, then decodes it:

```typescript
import * as decoding from 'lib0/decoding'
import { decode as decodeCBOR } from 'cbor-x'

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
    const subdocIndex: Record<string, Uint8Array> = decodeCBOR(cborData)
    provider.handleSubdocIndex(subdocIndex)
  } catch (error) {
    console.error('Failed to decode subdoc snapshot index:', error)
  }
}
```

The decoded object is a `Record<string, Uint8Array>` — keys are subdocument IDs, values are Yjs snapshots encoded with `Y.encodeSnapshot(Y.snapshot(doc))`. A snapshot includes both the state vector and delete set.

## Integration into YSweetProvider

### When to Send the Query

Send `MSG_QUERY_SUBDOCS` after the initial sync handshake completes — specifically, after `synced` becomes `true`. This is the same point at which the existing code re-subscribes to events.

The natural place is inside `websocket.onopen` in `setupWS`, right after flushing pending messages and re-subscribing to events:

```typescript
// In setupWS, inside websocket.onopen, after event re-subscription:

// Query subdoc snapshots for catch-up
if (provider.onSubdocIndex) {
  const encoderSubdocs = encoding.createEncoder()
  encoding.writeVarUint(encoderSubdocs, messageQuerySubdocs)
  encoding.writeVarUint(encoderSubdocs, 0) // all subdocs
  websocket.send(encoding.toUint8Array(encoderSubdocs))
}
```

Alternatively, send it from a `once('synced', ...)` handler if you want to wait until the parent document itself is fully synced before performing subdoc catch-up.

### Handling the Response

Add a method to `YSweetProvider`:

```typescript
export type SubdocIndexCallback = (
  staleDocIds: string[],
  allDocIds: string[],
) => void

// In YSweetProvider class:

onSubdocIndex: SubdocIndexCallback | null = null

/** Map of local snapshots by doc ID, populated by the consumer */
localSnapshots: Map<string, Uint8Array> = new Map()

handleSubdocIndex(serverIndex: Record<string, Uint8Array>) {
  const allDocIds = Object.keys(serverIndex)
  const staleDocIds: string[] = []

  for (const [docId, serverSnapshot] of Object.entries(serverIndex)) {
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

  this.onSubdocIndex?.(staleDocIds, allDocIds)
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

If you don't have any local snapshots (first connection), every subdocument will appear stale — which is correct. You sync everything on first connection.

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
                       │                               │
  5. Receive index     │<── MSG_SUBDOCS (8) ───────────│
                       │    {docId: snapshot, ...}      │
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

Steps 4-6 replace the naive approach of opening a sync connection to every subdocument.

## Integration Example: SharedFolder

In `SharedFolder.ts`, the existing `setupEventSubscriptions()` subscribes to `"document.updated"` for real-time updates. The subdoc index adds a catch-up step before that:

```typescript
// In SharedFolder, after provider is created and synced:

private async performSubdocCatchUp() {
  if (!this._provider) return

  // Collect local snapshots for all known documents
  const localSnapshots = new Map<string, Uint8Array>()
  for (const [guid, file] of this.files) {
    if (isDocument(file)) {
      const docId = `${this.relayId}-${guid}`
      const doc = await this.loadDocFromStorage(guid)
      if (doc) {
        localSnapshots.set(docId, Y.encodeSnapshot(Y.snapshot(doc)))
        doc.destroy()
      }
    }
  }

  this._provider.localSnapshots = localSnapshots
  this._provider.onSubdocIndex = (staleDocIds, allDocIds) => {
    // Sync only the stale documents
    for (const docId of staleDocIds) {
      this.syncDocument(docId)
    }
  }

  // Send the query (if already connected; otherwise it fires on next connect)
  if (this._provider.wsconnected) {
    const encoder = encoding.createEncoder()
    encoding.writeVarUint(encoder, 7) // messageQuerySubdocs
    encoding.writeVarUint(encoder, 0) // all subdocs
    this._provider.ws!.send(encoding.toUint8Array(encoder))
  }
}
```

## Edge Cases

### First Connection (No Local State)

If the client has no local snapshots (fresh install), every subdocument in the server's index will appear stale. This is correct — the client needs to sync everything. The index still helps by giving the client the full list of subdocument IDs in one round-trip.

### Empty Index

If the parent document has no subdocuments, the server returns an empty CBOR map (`{}`). The callback receives `staleDocIds = []` and `allDocIds = []`.

### Race: Updates During Catch-Up

If subdocuments are updated while the client is syncing stale ones, those updates are handled by the normal Yjs sync protocol on each subdocument's own WebSocket connection. Once the client subscribes to `document.updated` events on the parent, it receives real-time notifications for any further changes. The brief window between receiving the index and subscribing to events is safe because each individual subdoc sync uses the Yjs state exchange, which is idempotent.

### Invalid Frames

A tag-only `MSG_QUERY_SUBDOCS` frame is invalid. The client must always write the GUID count after message type 7, even when the count is `0`.

## Dependencies

The implementation uses the same dependencies already in the project:

- **lib0** (`encoding`, `decoding`) — message framing
- **cbor-x** (`decode`) — CBOR deserialization of the subdoc index
- **yjs** (`Y.snapshot`, `Y.encodeSnapshot`, `Y.decodeSnapshot`, `Y.equalSnapshots`) — snapshot operations
