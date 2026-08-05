# Fodpr TypeScript SDK

[Fodpr](https://github.com/LunaYoineko/Fodpr) (Fully Open Decentralized Protocol) のリレーサーバー向け **TypeScript SDK** です。
WebSocket 経由で署名付きイベントの投稿（EVENT）と購読要求（REQ）を行い、条件に一致するイベントを PUSH 形式でリアルタイムに受信できます。

> English version is available at [README.en.md](README.en.md)

## 特徴

- **イベント投稿 (EVENT)** — secp256k1 (ECDSA) で署名したイベントをリレーサーバーへ投稿
- **購読 (REQ / PUSH)** — 送信タイプ(JSON/String/Binary)やタグで条件を指定して、保存済みイベントを受信
- **鍵・署名ユーティリティ** — 秘密鍵生成 / 公開鍵導出 / 署名 / 署名検証（`CryptoUtils`）
- **ワイヤプロトコル** — サーバー(Nim 製 `protocol.nim`)とバイト単位で互換なエンコード / デコード（`Protocol`）
- **バイナリフレーム通信** — 公開鍵や署名など任意バイト列を正しく送受信（テキストフレームの UTF-8 文字化け問題を回避）
- **型定義付き** — `.d.ts` を同梱し、TypeScript で型安全に利用可能

## 必要環境

- Node.js 18 以上
- 接続先の Fodpr リレーサーバー（`ws://localhost:8000/` など）が起動していること
  - サーバーの起動方法は後述の「クイックスタート」を参照

## インストール

```bash
pnpm install
```

## ビルド

```bash
pnpm run build    # dist/ に JavaScript + 型定義(.d.ts) を出力
```

## クイックスタート

`examples/basic.ts` がそのまま動くサンプルです。

```bash
# 1. Fodpr のリポジトリをクローン
git clone https://github.com/LunaYoineko/FodprRelay

# 2. リレーサーバーを起動(別ターミナルで)
cd FodprRelay
docker compose up -d --build   # Docker で起動
# またはネイティブで起動:  nimble install -d && nim c -d:release src/server.nim && ./src/server

# SDK プロジェクトでサンプルを実行
pnpm run example
```

動作の流れ:

1. `ws://localhost:8000/` へ接続
2. 秘密鍵を生成し、公開鍵と署名を作成
3. `sendEvent()` でイベントを投稿（`transType` に JSON / String / Binary を指定）
   - サーバーが署名検証 → 保存（`OK: Event accepted`）
4. `sendReq()` で購読要求を送信
5. `onEvent()` で登録したコールバックが PUSH イベントを受信
6. 配信終了通知（`EOE: ...`）を受信

> #### 送信タイプ(transType)について
> - **JSON (1)**: `content` は UTF-8 の JSON。サーバーが JSON 構文を検証する。プロフィールのような構造化データを送る。**プロフィール管理はクライアント側の責務**であり、例えば `{"mode":"profile","name":"..."}` のように JSON を投稿し、取得した側で `mode` キーを見て判定する。
> - **String (2)**: `content` は UTF-8 の文字列。そのまま文字列として配信・表示される。
> - **Binary (3)**: `content` は任意のバイト列。バイナリフレームのまま配信される。
> - **All (0)**: REQ でのみ使用。すべてのタイプのイベントを購読する。

## 使い方

```ts
import { FodprClient, CryptoUtils, TransTypeString } from 'fodpr-ts-sdk';

// 1. サーバーへ接続
const client = new FodprClient("ws://localhost:8000/");
await client.connect();

// 2. PUSH イベント受信のコールバックを登録
client.onEvent((subId, event) => {
    console.log(`[受信] SubId: ${subId}, TransType: ${event.transType}`);
    console.log(`       Content: ${event.content}`);
});

// 3. テキスト応答("OK: ..." / "ERR: ..." / "EOE: ...")を受信
client.onText((message) => console.log(message));

// 4. 鍵ペアを作成し、content に対する署名を生成
//    サーバーは「送信する content と同じバイト列」の SHA-256 ダイジェストで署名を検証する。
const privKey = CryptoUtils.generatePrivateKey();
const pubkey = CryptoUtils.getRawCompressedPublicKey(privKey);
const content = "Hello, Fodpr!";
const signature = CryptoUtils.hexToBytes(
    await CryptoUtils.signMessage(privKey, new TextEncoder().encode(content))
);

// 5. イベントを投稿(transType は JSON / String / Binary から選択)
client.sendEvent({
    transType: TransTypeString,
    createdAt: Math.floor(Date.now() / 1000),
    pubkey,
    tags: ["test"],
    content,
    signature,
});

// 6. transType に一致するイベントを購読(0 = All ですべて購読)
client.sendReq({ subId: "sub_1", transType: TransTypeString, tagKey: "", tagVal: "" });
```

## API リファレンス

### `FodprClient`

| メソッド | 説明 |
|----------|------|
| `constructor(url?, options?)` | サーバー URL（既定: `ws://localhost:8000/`）。`options.verbose` で内部ログ出力が可能 |
| `connect(): Promise<void>` | サーバーへ接続。接続確立で resolve される |
| `sendEvent(event)` | 署名付きイベントを投稿（EVENT） |
| `sendReq(req)` | 購読要求を送信（REQ） |
| `onEvent(cb)` | PUSH イベント受信時のコールバック `(subId, event) => void` を登録 |
| `onText(cb)` | テキスト応答（`OK: ...` / `ERR: ...` / `EOE: ...`）受信時のコールバックを登録 |
| `close()` | 接続を閉じる |

### `CryptoUtils`

| メソッド | 説明 |
|----------|------|
| `generatePrivateKey(): string` | ランダムな秘密鍵（32 バイト）を HEX で生成 |
| `getRawCompressedPublicKey(privKey): Uint8Array` | 秘密鍵から圧縮公開鍵（33 バイト）を導出 |
| `getPublicKey(privKey): string` | 圧縮公開鍵を HEX 文字列で返す |
| `signMessage(privKey, message): Promise<string>` | メッセージに対する ECDSA 署名（compact 64 バイト HEX）。SHA-256 ダイジェストに対して署名 |
| `verifySignature(pubKey, message, sig): Promise<boolean>` | 署名の検証 |
| `hexToBytes(hex)` / `bytesToHex(bytes)` | HEX ↔ バイト列の変換 |

### `Protocol`

| メソッド | 説明 |
|----------|------|
| `encodeEvent(event): Uint8Array` | イベント本体をバイナリへエンコード |
| `decodeEvent(bytes): FodprEvent` | バイナリからイベントを復元 |
| `encodeReq(req): Uint8Array` | REQ パケット（先頭に種別バイト 0x02 を含む）をエンコード |
| `transTypeName(transType): string` | 送信タイプ数値から表示名を返す |

### 型定義

- `FodprEvent` — `{ transType, createdAt, pubkey, tags, content, signature }`
- `FodprReq` — `{ subId, transType, tagKey, tagVal }`
- 送信タイプ定数 — `TransTypeAll` (0) / `TransTypeJSON` (1) / `TransTypeString` (2) / `TransTypeBinary` (3)
- メッセージ種別定数 — `MsgTypeEvent` (0x01) / `MsgTypeReq` (0x02) / `MsgTypePush` (0x81)

## プロトコル概要

バイナリプロトコル（すべてビッグエンディアン）。詳細は [Fodpr の README](https://github.com/LunaYoineko/Fodpr) を参照。

```
EVENT: [0x01] transType(2) | createdAt(8) | pubkey(33) | tagCount(2) | (tagLen(2)|tag)* | contentLen(4) | content | signature(64)
REQ  : [0x02] subIdLen(2) | subId | transType(2) | tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
PUSH : [0x81] subIdLen(2) | subId | EVENT 本体
```

- `signature` は `content` の SHA-256 ダイジェストに対する secp256k1 署名（compact 形式 64 バイト）
- 通信はすべて **バイナリフレーム** で行われます
- サーバーは `content` の意味(プロフィール管理など)を解釈せず、`transType` ごとのストレージに追記保存します

## ディレクトリ構成

```
FodprTSSDK/
├── src/
│   ├── index.ts      # ライブラリの公開エントリーポイント(再エクスポート)
│   ├── client.ts     # FodprClient(WebSocket クライアント)
│   ├── protocol.ts   # ワイヤプロトコルのエンコード / デコード
│   └── crypto.ts     # 鍵生成・署名・検証ユーティリティ
├── examples/
│   └── basic.ts      # 基本的な利用例(EVENT 投稿 + REQ 購読)
├── dist/             # ビルド出力(JavaScript + .d.ts)
├── tsconfig.json
├── package.json
└── README.en.md
```

## ライセンス

MIT
