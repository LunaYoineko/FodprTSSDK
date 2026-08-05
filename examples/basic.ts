/**
 * basic.ts
 * --------
 * Fodpr TS SDK の基本的な利用例(例: イベント投稿 + 購読)。
 *
 * 実行方法:
 *   pnpm install
 *   pnpm example
 *   (または npx tsx examples/basic.ts)
 *
 * 事前に Fodpr リレーサーバー(ws://localhost:8000/)が起動している必要がある。
 *
 * 動作の流れ:
 *   1. サーバーへ接続する
 *   2. 秘密鍵を生成し、公開鍵・署名を作る
 *   3. EVENT パケットを送信してイベントを投稿する
 *   4. REQ パケットを送信して購読し、PUSH で配信されるイベントを受信する
 */

import { FodprClient, CryptoUtils, FodprReq } from '../src';

async function runExample() {
    console.log("=== Fodpr SDK 利用例 ===");

    // リレーサーバーへ接続する
    const client = new FodprClient("ws://localhost:8000/");

    try {
        await client.connect();
        console.log("[接続] リレーサーバーに接続しました");
    } catch (e) {
        console.error("サーバーへの接続に失敗しました。サーバーが起動しているか確認してください", e);
        return;
    }

    // 鍵ペアを生成する
    const privKeyHex = CryptoUtils.generatePrivateKey();
    const pubKeyBytes = CryptoUtils.getRawCompressedPublicKey(privKeyHex);
    console.log(`[鍵生成] 秘密鍵: ${privKeyHex}`);
    console.log(`[鍵生成] 公開鍵: ${CryptoUtils.bytesToHex(pubKeyBytes)}`);

    // 投稿するイベントの内容を用意する
    const kind = 1;                        // 1 = 通常のテキスト投稿
    const content = "Hello from TypeScript SDK!";
    const createdAt = Math.floor(Date.now() / 1000); // Unix 秒

    // サーバーは「送信する content と同じバイト列」に対する署名を検証する。
    // 別の文字列に署名すると署名検証に失敗して ERR: Invalid signature が返る。
    const contentBytes = new TextEncoder().encode(content);
    const signatureBytes = CryptoUtils.hexToBytes(await CryptoUtils.signMessage(privKeyHex, contentBytes));

    // PUSH イベント受信のコールバックを登録(購読後、条件に合うイベントが届く)
    client.onEvent((subId, event) => {
        console.log(`[受信] PUSH Event [SubId: ${subId}] Kind: ${event.kind}`);
        console.log(`       Content: ${event.content}`);
    });

    // サーバーからのテキスト応答("OK: ..." / "ERR: ..." / "EOE: ...")を受信
    client.onText((message) => {
        console.log(`[受信] ${message}`);
    });

    // イベント投稿(EVENT)。サーバー側で署名検証 → 保存される。
    client.sendEvent({
        kind,
        createdAt,
        pubkey: pubKeyBytes,
        tags: ["test-tag", "fodpr"],
        content,
        signature: signatureBytes,
    });

    // 少し待ってから購読要求(REQ)。保存済みの kind=1 イベントが PUSH で返る。
    setTimeout(() => {
        const reqData: FodprReq = {
            subId: "sub_ts_example_001",
            kind,
            tagKey: "",
            tagVal: "",
        };
        console.log(`[送信] REQ パケット送信 [SubId: ${reqData.subId}, Kind: ${reqData.kind}]`);
        client.sendReq(reqData);
    }, 1000);

    // 4 秒後にテストを終了して切断する
    setTimeout(() => {
        console.log("[完了] すべてのシーケンスが完了しました。切断します。");
        client.close();
        process.exit(0);
    }, 4000);
}

runExample();
