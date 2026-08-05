# Fodpr TypeScript SDK

A **TypeScript SDK** for [Fodpr](https://github.com/LunaYoineko/Fodpr) (Fully Open Decentralized Protocol) relay servers.
It posts signed events (EVENT) and sends subscription requests (REQ) over WebSocket, receiving matching events in real time via PUSH.

> 日本語版は [README.md](README.md) を参照してください。

## Features

- **Event posting (EVENT)** — Post secp256k1 (ECDSA) signed events to a relay server
- **Subscription (REQ / PUSH)** — Receive stored events filtered by kind and tags
- **Key & signing utilities** — Private key generation / public key derivation / signing / verification (`CryptoUtils`)
- **Wire protocol** — Encode/decode byte-compatible with the server (Nim `protocol.nim`) (`Protocol`)
- **Binary frame transport** — Arbitrary byte sequences such as public keys and signatures are transmitted correctly (avoids the UTF-8 mangling of text frames)
- **Type definitions** — Ships `.d.ts`, fully typed for TypeScript

## Requirements

- Node.js 18 or later
- A running Fodpr relay server (e.g. `ws://localhost:8000/`)
  - See the [Fodpr](https://github.com/LunaYoineko/Fodpr) repository README for how to start the server

## Installation

```bash
pnpm install
```

## Build

```bash
pnpm run build    # outputs JavaScript + type declarations (.d.ts) to dist/
```

## Quick Start

`examples/basic.ts` is a runnable sample.

```bash
# Start the relay server first (in another terminal)
docker compose up -d --build   # or ./src/server

# Run the sample
pnpm run example
```

Flow:

1. Connect to `ws://localhost:8000/`
2. Generate a private key, then derive the public key and create a signature
3. Post an event with `sendEvent()` (the server verifies the signature and stores it, returning `OK: Event accepted`)
4. Send a subscription request with `sendReq()`
5. A callback registered with `onEvent()` receives the PUSH event
6. Receive the end-of-events notice (`EOE: ...`)

## Usage

```ts
import { FodprClient, CryptoUtils } from 'fodpr-ts-sdk';

// 1. Connect to the server
const client = new FodprClient("ws://localhost:8000/");
await client.connect();

// 2. Register a callback for received PUSH events
client.onEvent((subId, event) => {
    console.log(`[received] SubId: ${subId}, Kind: ${event.kind}`);
    console.log(`           Content: ${event.content}`);
});

// 3. Receive text responses ("OK: ..." / "ERR: ..." / "EOE: ...")
client.onText((message) => console.log(message));

// 4. Create a key pair and sign the content
const privKey = CryptoUtils.generatePrivateKey();
const pubkey = CryptoUtils.getRawCompressedPublicKey(privKey);
const content = "Hello, Fodpr!";
const signature = CryptoUtils.hexToBytes(
    await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content))
);

// 5. Post an event
client.sendEvent({ kind: 1, createdAt: Math.floor(Date.now() / 1000), pubkey, tags: ["test"], content, signature });

// 6. Subscribe to kind=1 events (stored events are returned via PUSH)
client.sendReq({ subId: "sub_1", kind: 1, tagKey: "", tagVal: "" });
```

## API Reference

### `FodprClient`

| Method | Description |
|--------|-------------|
| `constructor(url?, options?)` | Server URL (default: `ws://localhost:8000/`). `options.verbose` enables internal logging |
| `connect(): Promise<void>` | Connect to the server. Resolves once the connection is established |
| `sendEvent(event)` | Post a signed event (EVENT) |
| `sendReq(req)` | Send a subscription request (REQ) |
| `onEvent(cb)` | Register a callback `(subId, event) => void` for PUSH events |
| `onText(cb)` | Register a callback for text responses (`OK: ...` / `ERR: ...` / `EOE: ...`) |
| `close()` | Close the connection |

### `CryptoUtils`

| Method | Description |
|--------|-------------|
| `generatePrivateKey(): string` | Generate a random private key (32 bytes) as HEX |
| `getRawCompressedPublicKey(privKey): Uint8Array` | Derive the compressed public key (33 bytes) |
| `getPublicKey(privKey): string` | Return the compressed public key as a HEX string |
| `signMessage(privKey, message): Promise<string>` | ECDSA signature over the message (compact 64-byte HEX). Signs the SHA-256 digest |
| `verifySignature(pubKey, message, sig): Promise<boolean>` | Verify a signature |
| `hexToBytes(hex)` / `bytesToHex(bytes)` | HEX ↔ bytes conversion |

### `Protocol`

| Method | Description |
|--------|-------------|
| `encodeEvent(event): Uint8Array` | Encode an event body to binary |
| `decodeEvent(bytes): FodprEvent` | Restore an event from binary |
| `encodeReq(req): Uint8Array` | Encode a REQ packet (includes the leading type byte 0x02) |

### Types

- `FodprEvent` — `{ kind, createdAt, pubkey, tags, content, signature }`
- `FodprReq` — `{ subId, kind, tagKey, tagVal }`
- Message type constants — `MsgTypeEvent` (0x01) / `MsgTypeReq` (0x02) / `MsgTypePush` (0x81)

## Protocol Overview

Binary protocol, all integers big-endian. See the [Fodpr README](https://github.com/LunaYoineko/Fodpr) for details.

```
EVENT: [0x01] kind(2) | createdAt(8) | pubkey(33) | tagCount(2) | (tagLen(2)|tag)* | contentLen(4) | content | signature(64)
REQ  : [0x02] subIdLen(2) | subId | kind(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
PUSH : [0x81] subIdLen(2) | subId | EVENT body
```

- `signature` is a secp256k1 signature (compact 64 bytes) over the SHA-256 digest of `content`
- All communication uses **binary frames**

## Project Structure

```
FodprTSSDK/
├── src/
│   ├── index.ts      # Public entry point (re-exports)
│   ├── client.ts     # FodprClient (WebSocket client)
│   ├── protocol.ts   # Wire protocol encode/decode
│   └── crypto.ts     # Key generation, signing and verification utilities
├── examples/
│   └── basic.ts      # Basic usage (EVENT posting + REQ subscription)
├── dist/             # Build output (JavaScript + .d.ts)
├── tsconfig.json
└── package.json
```

## License

MIT
