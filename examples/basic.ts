/**
 * basic.ts
 * --------
 * Fodpr TypeScript SDK の基本的な利用例。
 *
 * 動作の流れ:
 *   1. サーバーへ接続する
 *   2. 秘密鍵を生成し、公開鍵と署名を作成する
 *   3. TransTypeString のイベント(平文)を投稿する
 *   4. TransTypeJSON のイベント(JSON)を「プロフィール」として投稿する
 *      (プロフィール管理はクライアント側の責務。content は `{"mode":"profile", ...}`)
 *   5. REQ で購読して、PUSH で配信されるイベントを受信する
 *
 * 実行方法:
 *   pnpm install
 *   pnpm run example
 *
 * 事前に Fodpr リレーサーバー(ws://localhost:8000/)が起動していること。
 */

import { FodprClient, CryptoUtils, Protocol, FodprReq, TransTypeJSON, TransTypeString } from '../src';

async function runExample() {
    console.log("=== Fodpr TypeScript SDK 利用例 ===");

    // リレーサーバーへ接続する
    const client = new FodprClient("ws://localhost:8000/");

    // PUSH イベント受信のコールバックを登録
    client.onEvent((subId, event) => {
        console.log(`[受信] PUSH [SubId: ${subId}] TransType: ${Protocol.transTypeName(event.transType)}`);
        console.log(`       Content: ${event.content}`);
    });

    // テキスト応答("OK: ..." / "ERR: ..." / "EOE: ...")を受信
    client.onText((message) => console.log(`[受信] ${message}`));

    try {
        await client.connect();
        console.log("[接続] リレーサーバーに接続しました");
    } catch (e) {
        console.error("サーバーへの接続に失敗しました。サーバーが起動しているか確認してください", e);
        return;
    }

    // 鍵ペアを生成する
    const privKey = CryptoUtils.generatePrivateKey();
    const pubkey = CryptoUtils.getRawCompressedPublicKey(privKey);
    console.log(`[鍵生成] 公開鍵: ${CryptoUtils.bytesToHex(pubkey)}`);

    const encoder = new TextEncoder();

    // --- (3) TransTypeString : 平文を投稿する ---
    const stringContent = "Hello from TypeScript SDK!";
    const stringSig = CryptoUtils.hexToBytes(
        await CryptoUtils.signMessage(privKey, encoder.encode(stringContent))
    );
    console.log("[送信] TransTypeString のイベントを投稿します...");
    client.sendEvent({
        transType: TransTypeString,
        createdAt: Math.floor(Date.now() / 1000),
        pubkey,
        tags: ["test-tag", "fodpr"],
        content: stringContent,
        signature: stringSig,
    });

    // --- (4) TransTypeJSON : JSON として「プロフィール」を投稿する ---
    // プロフィール管理はクライアント側の責務。content は JSON で、
    // 取得した側が "mode":"profile" を見てプロフィールとして扱う。
    // (サーバーは JSON 構文を検証するため、必ず有効な JSON を送ること)
    const profile = { mode: "profile", name: "FodprTaro", about: "TypeScript SDK からの投稿" };
    const jsonContent = JSON.stringify(profile);
    const jsonSig = CryptoUtils.hexToBytes(
        await CryptoUtils.signMessage(privKey, encoder.encode(jsonContent))
    );
    console.log("[送信] TransTypeJSON のイベント(プロフィール)を投稿します...");
    client.sendEvent({
        transType: TransTypeJSON,
        createdAt: Math.floor(Date.now() / 1000),
        pubkey,
        tags: [],
        content: jsonContent,
        signature: jsonSig,
    });

    // --- (5) REQ : すべてのタイプを購読してPUSHを受信する ---
    setTimeout(() => {
        const reqData: FodprReq = {
            subId: "sub_ts_example_001",
            transType: 0, // 0 = TransTypeAll : すべてのタイプを購読
            tagKey: "",
            tagVal: "",
        };
        console.log(`[送信] REQ パケット送信 [SubId: ${reqData.subId}, TransType: All]`);
        client.sendReq(reqData);
    }, 1000);

    // 4秒後にテストを終了して切断する
    setTimeout(() => {
        console.log("[完了] すべてのシーケンスが完了しました。切断します。");
        client.close();
        process.exit(0);
    }, 4000);
}

runExample();
