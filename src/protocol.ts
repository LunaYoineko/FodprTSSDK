/**
 * protocol.ts
 * -----------
 * Fodpr のワイヤプロトコルを定義するモジュール。
 *
 * サーバー(Nim 製)の protocol.nim とバイト単位で互換性がある。
 * 数値はすべて「ビッグエンディアン(ネットワークバイトオーダー)」で
 * エンコードされる。
 *
 * パケット構造(先頭 1 バイトがメッセージ種別):
 *   - 0x01 (EVENT): イベント投稿(署名付き)
 *   - 0x02 (REQ)  : サブスクリプション(購読)要求
 *   - 0x81 (PUSH) : サーバー → クライアントのイベント配信
 */

// メッセージ種別を表す定数。
// Nim 側 protocol.nim の MsgTypeEvent / MsgTypeReq / MsgTypePush と一致させること。
export const MsgTypeEvent = 0x01; // イベント投稿 (クライアント -> サーバー)
export const MsgTypeReq = 0x02;   // 購読要求 (クライアント -> サーバー)
export const MsgTypePush = 0x81;  // イベント配信 (サーバー -> クライアント)

// 送信タイプ (TransType)。
// イベントの `content` がどのようなデータであるかを表し、配信方法を切り替える。
// Nim 側の TransTypeAll / TransTypeJSON / TransTypeString / TransTypeBinary と一致。
export const TransTypeAll = 0x00;    // すべてのタイプを購読する(REQ でのみ使用)
export const TransTypeJSON = 0x01;   // content は UTF-8 の JSON(サーバーが構文検証する)
export const TransTypeString = 0x02; // content は UTF-8 の文字列
export const TransTypeBinary = 0x03; // content は任意のバイト列(バイナリのまま配信)

// 投稿されるイベント本体。
export interface FodprEvent {
    transType: number;          // 送信タイプ(TransTypeJSON / String / Binary)
    createdAt: number;          // Unix タイムスタンプ(秒, uint64)
    pubkey: Uint8Array;         // 送信者の公開鍵(圧縮形式 33 バイト)
    tags: string[];             // タグ文字列のリスト
    content: string;            // 本文(タイプに応じて JSON / 文字列 / バイナリ)
    signature: Uint8Array;      // content の SHA-256 ダイジェストに対する ECDSA 署名(64 バイト)
}

// 購読 (REQ) 要求。
// transType が TransTypeAll(0) の場合はすべてのタイプを購読する。
// tagKey/tagVal でタグの絞り込みも可能。
//   プロフィール管理はクライアント側の責務。例えば TransTypeJSON で
//   `{"mode":"profile","name":"..."}` のように JSON を投稿すると、サーバーは
//   content をそのまま保存し取得時も JSON として返す。クライアントが profile を判定する。
export interface FodprReq {
    subId: string;    // 購読を識別するための ID(サーバーはこの ID 付きで PUSH を返す)
    transType: number; // 購読したい送信タイプ(0 = すべて)
    tagKey: string;   // 絞り込み対象のタグキー(空文字なら無条件)
    tagVal: string;   // 絞り込み対象のタグ値(空文字なら無条件)
}

export class Protocol {
    /**
     * イベントをバイナリにエンコードする(Nim の encodeEvent 相当)。
     *
     * レイアウト(すべてビッグエンディアン):
     *   transType(2) | createdAt(8) | pubkey(33) | tagCount(2) |
     *   (tagLen(2) | tag) * tagCount | contentLen(4) | content | signature(64)
     *
     * メッセージ種別バイト(0x01)は含めない。
     * 送信時はクライアント側で先頭に種別バイトを付与する(encodeEvent の出力は「本体」)。
     */
    public static encodeEvent(event: FodprEvent): Uint8Array {
        const encoder = new TextEncoder();

        // 各タグを UTF-8 バイト列に変換しつつ、タグ部全体のサイズを事前計算する。
        // タグ部 = tagCount(uint16) + (tagLen(uint16) + tag本体) * 個数
        let tagsBytesLen = 2; // tagCount(uint16) 分
        const encodedTags: { len: number; bytes: Uint8Array }[] = [];
        for (const tag of event.tags) {
            const b = encoder.encode(tag);
            encodedTags.push({ len: b.length, bytes: b });
            tagsBytesLen += 2 + b.length; // 各タグの長さ(2) + 本体
        }

        const contentBytes = encoder.encode(event.content);

        // 全体サイズ: transType(2) + createdAt(8) + pubkey(33) + タグ部 + contentLen(4) + content + signature(64)
        const totalLen = 2 + 8 + 33 + tagsBytesLen + 4 + contentBytes.length + 64;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // transType (uint16, ビッグエンディアン)
        view.setUint16(offset, event.transType, false);
        offset += 2;

        // createdAt (uint64, ビッグエンディアン)
        view.setBigUint64(offset, BigInt(event.createdAt), false);
        offset += 8;

        // pubkey(圧縮形式 33 バイト)を検証してから書き込む
        const pubkeyBytes = event.pubkey;
        if (pubkeyBytes.length != 33) {
            throw new Error(`Invalid pubkey length: expected 33, got ${pubkeyBytes.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(pubkeyBytes);
        offset += 33;

        // tagCount (uint16, ビッグエンディアン)
        view.setUint16(offset, event.tags.length, false);
        offset += 2;

        // 各タグを「長さ(2) + 本体」の形式で書き込む
        for (const t of encodedTags) {
            view.setUint16(offset, t.len, false);
            offset += 2;
            new Uint8Array(buffer, offset, t.bytes.length).set(t.bytes);
            offset += t.bytes.length;
        }

        // content の長さ(uint32)と本体
        view.setUint32(offset, contentBytes.length, false);
        offset += 4;
        new Uint8Array(buffer, offset, contentBytes.length).set(contentBytes);
        offset += contentBytes.length;

        // signature(compact 形式 64 バイト)を検証してから書き込む
        if (event.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${event.signature.length}`);
        }
        new Uint8Array(buffer, offset, 64).set(event.signature);

        return new Uint8Array(buffer);
    }

    /**
     * 購読要求(REQ)をバイナリにエンコードする(Nim の encodeReq 相当)。
     *
     * Nim の encodeReq と同様に、先頭にメッセージ種別バイト(0x02)を
     * 含めた「送信するパケット全体」を返す。
     *
     * レイアウト(すべてビッグエンディアン):
     *   MsgTypeReq(1) | subIdLen(2) | subId | transType(2) |
     *   tagKeyLen(2) | tagKey | tagValLen(2) | tagVal
     */
    public static encodeReq(req: FodprReq): Uint8Array {
        const encoder = new TextEncoder();
        const subIdBytes = encoder.encode(req.subId);
        const tagKeyBytes = encoder.encode(req.tagKey);
        const tagValBytes = encoder.encode(req.tagVal);

        const totalLen = 1 + 2 + subIdBytes.length + 2 + 2 + tagKeyBytes.length + 2 + tagValBytes.length;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // メッセージ種別(REQ)
        view.setUint8(offset, MsgTypeReq);
        offset += 1;

        // subId(長さ uint16 + 本体)
        view.setUint16(offset, subIdBytes.length, false);
        offset += 2;
        new Uint8Array(buffer, offset, subIdBytes.length).set(subIdBytes);
        offset += subIdBytes.length;

        // transType (uint16, ビッグエンディアン)
        view.setUint16(offset, req.transType, false);
        offset += 2;

        // tagKey(長さ uint16 + 本体)
        view.setUint16(offset, tagKeyBytes.length, false);
        offset += 2;
        new Uint8Array(buffer, offset, tagKeyBytes.length).set(tagKeyBytes);
        offset += tagKeyBytes.length;

        // tagVal(長さ uint16 + 本体)
        view.setUint16(offset, tagValBytes.length, false);
        offset += 2;
        new Uint8Array(buffer, offset, tagValBytes.length).set(tagValBytes);
        offset += tagValBytes.length;

        return new Uint8Array(buffer);
    }

    /**
     * encodeEvent の出力(イベント本体バイト列)を FodprEvent へ復元する(Nim の decodeEvent 相当)。
     * PUSH パケットの「イベント本体」部分を渡すことを想定している。
     */
    public static decodeEvent(data: Uint8Array): FodprEvent {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();
        let offset = 0;

        // transType (uint16, ビッグエンディアン)
        const transType = view.getUint16(offset, false);
        offset += 2;

        // createdAt (uint64, ビッグエンディアン)
        const createdAt = Number(view.getBigUint64(offset, false));
        offset += 8;

        // pubkey(圧縮形式 33 バイト)
        const pubkey = data.slice(offset, offset + 33);
        offset += 33;

        // tagCount(uint16) を読んで、タグを個数分復元する
        const tagCount = view.getUint16(offset, false);
        offset += 2;
        const tags: string[] = [];
        for (let i = 0; i < tagCount; i++) {
            const tLen = view.getUint16(offset, false);
            offset += 2;
            tags.push(decoder.decode(data.subarray(offset, offset + tLen)));
            offset += tLen;
        }

        // content(長さ uint32 + 本体)
        const contentLen = view.getUint32(offset, false);
        offset += 4;
        const content = decoder.decode(data.subarray(offset, offset + contentLen));
        offset += contentLen;

        // signature(compact 形式 64 バイト)
        const signature = data.slice(offset, offset + 64);

        return { transType, createdAt, pubkey, tags, content, signature };
    }

    /**
     * 送信タイプ(TransType)の数値から表示用の名前を返す(ログ表示用)。
     * Nim 側の transTypeName に相当。
     */
    public static transTypeName(transType: number): string {
        switch (transType) {
            case TransTypeAll:    return "All";
            case TransTypeJSON:   return "JSON";
            case TransTypeString: return "String";
            case TransTypeBinary: return "Binary";
            default:              return `Unknown(${transType})`;
        }
    }
}
