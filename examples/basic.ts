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
 *   5. TransTypeSigned のイベント(全体署名)を投稿する
 *   6. REQ で購読して、PUSH で配信されるイベントを受信する
 *
 * 実行方法:
 *   pnpm install
 *   pnpm run example
 *
 * 事前に Fodpr リレーサーバー(ws://localhost:8000/)が起動していること。
 */

import { FodprClient, CryptoUtils, Protocol, FodprReq, FodprEvent } from '../src';
import {
    TransTypeAll, TransTypeJSON, TransTypeString, TransTypeSigned,
} from '../src';

async function runExample() {
    console.log("=== Fodpr TypeScript SDK 利用例 ===");

    // リレーサーバーへ接続する
    const privKey = CryptoUtils.generatePrivateKey();
    console.log("[鍵生成] fsec:", CryptoUtils.fsecEncode(privKey));
    console.log("[鍵生成] fpub:", CryptoUtils.fpubEncode(CryptoUtils.getPublicKey(privKey)));

    const client = new FodprClient("ws://localhost:8000/", { privateKey: privKey, verbose: true });

    // PUSH イベント受信のコールバックを登録
    client.onEvent((subId, event) => {
        const contentStr = new TextDecoder().decode(event.content);
        console.log(`[受信] PUSH [SubId: ${subId}] TransType: ${Protocol.transTypeName(event.transType)}`);
        console.log(`       Content: ${contentStr}`);
    });

    // テキスト応答("OK: ..." / "ERR: ..." / "EOE: ..." / "CHALLENGE: ...")を受信
    client.onText((message) => console.log(`[受信] ${message}`));

    try {
        await client.connect();
        console.log("[接続] リレーサーバーに接続しました");
    } catch (e) {
        console.error("サーバーへの接続に失敗しました。サーバーが起動しているか確認してください", e);
        return;
    }

    const pubkey = CryptoUtils.getRawCompressedPublicKey(privKey);
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
        content: encoder.encode(stringContent),
        signature: stringSig,
    });

    // --- (4) TransTypeJSON : JSON として「プロフィール」を投稿する ---
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
        content: encoder.encode(jsonContent),
        signature: jsonSig,
    });

    // --- (5) TransTypeSigned : 全体署名付きイベントを投稿する ---
    // TransTypeSigned は createdAt / pubkey / tags / content の全フィールドに署名する。
    // イベントID (eventId) は署名対象バイト列の SHA-256 で計算できる。
    const signedContent = "これは全体署名付きイベントです";
    const signedEvent: FodprEvent = {
        transType: TransTypeSigned,
        createdAt: Math.floor(Date.now() / 1000),
        pubkey,
        tags: [],
        content: encoder.encode(signedContent),
        signature: new Uint8Array(64), // placeholder
    };
    // 署名対象バイト列をエンコード (signature フィールドは除外される)
    const signedData = Protocol.encodeEventSignedData(signedEvent);
    // 署名を生成
    signedEvent.signature = await CryptoUtils.signEvent(privKey, signedData);
    console.log("[送信] TransTypeSigned のイベントを投稿します...");
    console.log(`       eventId: ${Protocol.eventIdHex(signedData)}`);
    client.sendEvent(signedEvent);

    // --- (6) REQ : すべてのタイプを購読してPUSHを受信する ---
    setTimeout(() => {
        const reqData: FodprReq = {
            subId: "sub_ts_example_001",
            transType: TransTypeAll, // 0 = TransTypeAll : すべてのタイプを購読
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
