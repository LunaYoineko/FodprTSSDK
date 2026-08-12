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
 *   - 0x03 (DEL)  : イベント削除要求(署名付き)
 *   - 0x04 (AUTH) : 認証応答 (NIP-42 相当)
 *   - 0x05 (SIGNAL) : WebRTC シグナリングメッセージ
 *   - 0x06 (DATA) : WebRTCデータチャネルメッセージ (P2P直接, 署名付き)
 *   - 0x07 (PEER_LIST_REQ) : F2F: ピアリスト要求
 *   - 0x08 (WOT_INTRO) : F2F: WoT紹介
 *   - 0x09 (INVITATION_REQ) : F2F: インビテーション要求
 *   - 0x0A (GROUP_REQ) : F2F: グループ管理要求
 *   - 0x81 (PUSH) : サーバー → クライアントのイベント配信
 *   - 0x82 (CHALLENGE) : サーバー → クライアントの認証チャレンジ
 *   - 0x83 (SIGNAL_PUSH) : サーバー → クライアントのシグナリング配信
 *   - 0x84 (DATA_PUSH) : WebRTCデータ配信 (リレー経由の場合)
 *   - 0x87 (PEER_LIST_PUSH) : F2F: ピアリスト配信
 *   - 0x88 (WOT_INTRO_PUSH) : F2F: WoT紹介配信
 *   - 0x89 (INVITATION_PUSH) : F2F: インビテーション配信
 *   - 0x8A (GROUP_PUSH) : F2F: グループ管理配信
 */

import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import { CryptoUtils } from './crypto';

// メッセージ種別を表す定数。
// Nim 側 protocol.nim の MsgType* と一致。
// P2P メッシュ (WebRTC データチャネル) 用。リレー・ホストは存在せず、
// すべてクライアント間で直接やり取りする。
export const MsgTypeEvent = 0x01;       // 署名付きイベント (投稿・ゴシップ配信)
export const MsgTypeSignal = 0x05;      // WebRTC シグナリング (offer/answer/ICE, P2P)
export const MsgTypeData = 0x06;        // WebRTCデータチャネルメッセージ (P2P直接, 署名付き)
export const MsgTypePeerListReq = 0x07; // F2F: ピアリスト要求 (ピア -> ピア)
export const MsgTypeWoTIntro = 0x08;    // F2F: WoT紹介 (ピア -> ピア)
export const MsgTypeInvitationReq = 0x09; // F2F: インビテーション要求 (ピア -> ピア)
export const MsgTypeDht = 0x0B;         // DHT RPC (Kademlia: PING / FIND_NODE / FIND_VALUE / STORE)
export const MsgTypePeerListPush = 0x87; // F2F: ピアリスト配信 (ピア -> クライアント)
export const MsgTypeWoTIntroPush = 0x88; // F2F: WoT紹介配信 (ピア -> クライアント)
export const MsgTypeInvitationPush = 0x89; // F2F: インビテーション配信 (ピア -> クライアント)
export const MsgTypeDhtNodes = 0x8B;    // DHT: 近傍ノード応答 (FIND_NODE / FIND_VALUE の非ヒット時)
export const MsgTypeDhtValue = 0x8C;    // DHT: 値応答 (FIND_VALUE ヒット / STORE 完了)

// 送信タイプ (TransType)。
// イベントの `content` がどのようなデータであるかを表し、配信方法を切り替える。
// Nim 側の TransTypeJSON / TransTypeString / TransTypeBinary /
// TransTypeSigned / TransTypeEncrypted / TransTypeData /
// TransTypePeerList / TransTypeWoTIntro / TransTypeInvitation と一致。
export const TransTypeJSON = 0x01;     // content は UTF-8 の JSON
export const TransTypeString = 0x02;   // content は UTF-8 の文字列
export const TransTypeBinary = 0x03;   // content は任意のバイト列(バイナリのまま配信)
export const TransTypeSigned = 0x04;   // 拡張イベント(全体署名)。createdAt / pubkey / tags を含む全フィールドに署名する
export const TransTypeEncrypted = 0x05; // 暗号化イベント。content は envelope のエンベロープ
export const TransTypeData = 0x07;     // WebRTCデータチャネル専用。P2P直接通信で使用。各メッセージに署名を付与する
export const TransTypePeerList = 0x09;   // F2F: ピアリスト交換 (WoTキャッシュ同期) 専用
export const TransTypeWoTIntro = 0x0A;   // F2F: WoT紹介メッセージ専用
export const TransTypeInvitation = 0x0B; // F2F: インビテーションコード専用

// シグナリングメッセージの種別 (SignalType)。
// Nim 側 protocol.nim の SignalOffer / SignalAnswer / SignalCandidate と一致。
export const SignalOffer = 1;        // SDP Offer (IPv6 一時アドレスを含む候補)
export const SignalAnswer = 2;       // SDP Answer
export const SignalCandidate = 3;    // ICE Candidate (IPv6 一時アドレスを含む)

// DHT 操作種別 (DhtOp)。
// Nim 側 protocol.nim の DhtOp* と一致。
export const DhtOpPing = 0;         // PING: 生存確認
export const DhtOpPong = 1;         // PONG: 生存応答
export const DhtOpFindNode = 2;     // FIND_NODE: 近傍ノード探索
export const DhtOpFindValue = 3;    // FIND_VALUE: 値取得
export const DhtOpStore = 4;        // STORE: 値保存

// 投稿されるイベント本体。
// content は文字列 (TransTypeJSON / String) またはバイナリデータ (TransTypeBinary / Encrypted) を
// Uint8Array として受け取り、エンコード/デコード時にそのままバイト列として扱う。
// 文字列コンテンツの場合は TextEncoder でエンコードして渡すこと (例: new TextEncoder().encode("hello"))
export interface FodprEvent {
    transType: number;          // 送信タイプ(TransTypeJSON / String / Binary / Signed / Encrypted)
    createdAt: number;          // Unix タイムスタンプ(秒, uint64)
    pubkey: Uint8Array;         // 送信者の公開鍵(圧縮形式 33 バイト)
    tags: string[];             // タグ文字列のリスト
    content: Uint8Array;        // 本文(タイプに応じて JSON / 文字列 / バイナリのバイト列)
    signature: Uint8Array;      // 署名(compact 形式 64 バイト)
}

// WebRTC シグナリングメッセージ (P2P メッシュ)。
// リレーは存在せず、確立前の相手へはメッシュの既存データチャネル経由で
// 転送される (受信側で target を見て転送/受領)。双方は署名を検証する。
export interface FodprSignal {
    signalType: number;           // SignalOffer / SignalAnswer / SignalCandidate
    sender: Uint8Array;           // 送信者の公開鍵 (圧縮形式 33 バイト)
    target: Uint8Array;           // 宛先の公開鍵
    content: string;              // SDP JSON / ICE candidate JSON (IPv6 一時アドレス含む)
    signature: Uint8Array;        // 上記フィールド全体の ECDSA 署名 (64 バイト)
}

// WebRTCデータチャネルメッセージ (P2P直接通信用)。
// 各メッセージに署名を付与し、送信者の身元とメッセージの完全性を保証する。
// IPv6 一時アドレス等のメタデータを tags に含める。
export interface FodprData {
    sender: Uint8Array;           // 送信者の公開鍵 (圧縮形式 33 バイト)
    target: Uint8Array;           // 宛先の公開鍵
    seq: number;                  // シーケンス番号 (リプレイ攻撃防止, uint64)
    timestamp: number;            // Unix タイムスタンプ (秒, uint64)
    tags: string[];               // メタデータタグ (例: "ipv6:<temp_addr>", "type:text")
    content: Uint8Array;          // ペイロード (バイナリ)
    signature: Uint8Array;        // 上記全フィールドの ECDSA 署名 (64 バイト)
}

// F2F: ピア情報 (ピアキャッシュ・WoT・DHT 用)
export interface PeerInfo {
    pubkey: Uint8Array;          // 公開鍵 (圧縮形式 33 バイト)
    addresses: string[];         // 接続アドレス (IPv6一時アドレス, WebSocket URL等)
    lastSeen: number;            // 最後に見た時刻 (Unix秒, uint64)
    trustScore: number;          // 信頼スコア (0.0-1.0, float32)
}

// F2F: ピアリスト交換 (TransTypePeerList 用)
// 最大50件のピア情報を署名付きで交換 (WoTキャッシュ同期)
export interface PeerList {
    version: number;              // キャッシュバージョン (uint64)
    peerCount: number;            // ピア数 (uint16, 最大50)
    peers: PeerInfo[];            // ピア情報リスト
    signature: Uint8Array;        // 全体の署名 (送信者の秘密鍵で署名)
}

// F2F: WoT紹介メッセージ (TransTypeWoTIntro 用)
// 新しいピアを信頼チェーン付きで紹介 (シビル耐性)
export interface WoTIntro {
    introducer: Uint8Array;       // 紹介者の公開鍵 (圧縮形式 33 バイト)
    newPeer: PeerInfo;            // 紹介する新しいピアの情報
    signature: Uint8Array;        // 紹介者の署名 (紹介者の秘密鍵で署名)
}

// F2F: インビテーションコード (TransTypeInvitation 用)
// 第1救済手段。知人から共有される招待データ (Bech32エンコード形式: f2finv1...)
export interface InvitationCode {
    version: number;              // バージョン (uint8, 0x01)
    issuer: Uint8Array;            // 発行者の公開鍵 (圧縮形式 33 バイト)
    targetPeer: PeerInfo;         // 接続対象のピア情報
    expiresAt: number;            // 有効期限 (Unix秒, uint64)
    scope: number;                // 0=単発接続, 1=WoT招待 (cache共有含む) (uint8)
    signature: Uint8Array;        // 発行者の署名 (秘密鍵で署名)
}

// DHT: 近傍ノード情報 (Kademlia ルーティングテーブル / 応答用)
// nodeId = SHA-256(圧縮公開鍵) をノードIDとして使う。
export interface DhtNodeInfo {
    nodeId: Uint8Array;          // SHA-256(compressed pubkey) (32 バイト)
    pubkey: Uint8Array;          // 公開鍵 (圧縮形式 33 バイト)
    addresses: string[];         // 接続アドレス ["[ipv6]:port", ...]
    lastSeen: number;            // 最後に見た時刻 (Unix秒, uint64)
    trustScore: number;          // WoT信頼スコア (0.0-1.0, 新規は最小値)
}

// DHT: RPC メッセージ (Kademlia over WebRTC データチャネル)。
// MsgTypeDht (0x0B) / MsgTypeDhtNodes (0x8B) / MsgTypeDhtValue (0x8C) の
// いずれかのパケット形式で運ばれる。sender で署名し、中継者による
// 改ざんを防ぐ。msgId で要求と応答を対応付ける。
export interface DhtMessage {
    op: number;                   // DhtOpPing / DhtOpPong / DhtOpFindNode / DhtOpFindValue / DhtOpStore
    msgId: Uint8Array;            // 乱数メッセージID (16 バイト, 応答照合用)
    key: Uint8Array;              // FIND_NODE / FIND_VALUE / STORE のキー (32 バイト)
    nodes: DhtNodeInfo[];         // FIND_NODE 応答: 近傍ノード (最大 k)
    value: Uint8Array;            // FIND_VALUE 応答: 値 / STORE ペイロード
    sender: Uint8Array;           // 送信ノードの公開鍵 (圧縮形式 33 バイト)
    signature: Uint8Array;        // op..sender 全体の ECDSA 署名 (64 バイト)
}

// F2F: シードサーバー応答のノード情報
export interface SeedNode {
    pubkey: Uint8Array;           // ノードの公開鍵 (圧縮形式 33 バイト)
    addresses: string[];          // 接続アドレス
}

// F2F: シードサーバー応答 (JSON)
//   { type: "seed_response", version: uint64, nodes: [{pubkey: hex, addresses: [...]}], signature: base64 }
export interface SeedResponse {
    type: "seed_response";
    version: number;
    nodes: SeedNode[];
    signature: Uint8Array;
}

export class Protocol {
    /**
     * イベントの署名対象バイト列 (signature を除く全フィールド) をエンコードする:
     *   transType(2) | createdAt(8) | pubkey(33) | tagCount(2) |
     *   (tagLen(2) | tag) * tagCount | contentLen(4) | content
     *
     * 用途:
     *   - TransTypeSigned (全体署名) の署名対象
     *   - イベントID (eventId) の算出対象 (このバイト列の SHA-256)
     */
    public static encodeEventSignedData(event: FodprEvent): Uint8Array {
        // 各タグを UTF-8 バイト列に変換しつつ、タグ部全体のサイズを事前計算する。
        const encoder = new TextEncoder();
        let tagsBytesLen = 2; // tagCount(uint16) 分
        const encodedTags: { len: number; bytes: Uint8Array }[] = [];
        for (const tag of event.tags) {
            const b = encoder.encode(tag);
            encodedTags.push({ len: b.length, bytes: b });
            tagsBytesLen += 2 + b.length;
        }

        // content は既に Uint8Array (バイナリ対応)
        const contentBytes = event.content;

        // 全体サイズ: transType(2) + createdAt(8) + pubkey(33) + タグ部 + contentLen(4) + content
        const totalLen = 2 + 8 + 33 + tagsBytesLen + 4 + contentBytes.length;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // transType (uint16, ビッグエンディアン)
        view.setUint16(offset, event.transType, false);
        offset += 2;

        // createdAt (uint64, ビッグエンディアン)
        view.setBigUint64(offset, BigInt(event.createdAt), false);
        offset += 8;

        // pubkey(圧縮形式 33 バイト)
        if (event.pubkey.length !== 33) {
            throw new Error(`Invalid pubkey length: expected 33, got ${event.pubkey.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(event.pubkey);
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

        return new Uint8Array(buffer);
    }

    /**
     * イベントをバイナリにエンコードする (Nim の encodeEvent 相当)。
     * レイアウト: encodeEventSignedData の結果に signature(64) を連結したもの。
     * メッセージ種別バイト(0x01)は含めない。送信時はクライアント側で先頭に種別バイトを付与する。
     */
    public static encodeEvent(event: FodprEvent): Uint8Array {
        const signedData = Protocol.encodeEventSignedData(event);

        // signature(compact 形式 64 バイト)を検証してから書き込む
        if (event.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${event.signature.length}`);
        }

        const totalLen = signedData.length + 64;
        const buffer = new Uint8Array(totalLen);
        buffer.set(signedData, 0);
        buffer.set(event.signature, signedData.length);
        return buffer;
    }

    /**
     * イベントID (eventId) を計算する (Nim の eventId 相当)。
     * eventId = SHA-256(encodeEventSignedData(event))
     */
    public static eventId(eventOrSignedData: FodprEvent | Uint8Array): Uint8Array {
        const signedData = eventOrSignedData instanceof Uint8Array
            ? eventOrSignedData
            : Protocol.encodeEventSignedData(eventOrSignedData);
        return sha256(signedData);
    }

    /**
     * イベントID の 16 進文字列表現を返す (Nim の eventIdHex 相当)。
     * タグ "e:<eventid>" などに使いやすい。
     */
    public static eventIdHex(eventOrSignedData: FodprEvent | Uint8Array): string {
        const id = Protocol.eventId(eventOrSignedData);
        let hex = '';
        for (let i = 0; i < id.length; i++) {
            hex += id[i].toString(16).padStart(2, '0');
        }
        return hex;
    }

    /**
     * TransTypeSigned / TransTypeEncrypted イベントの署名対象バイト列を生成する
     * (Nim の signEvent 相当)。エンコード前に ev.signature は空のまま呼ぶこと。
     */
    public static encodeEventSignedDataForSig(event: FodprEvent): Uint8Array {
        return Protocol.encodeEventSignedData(event);
    }

    /**
     * encodeEvent の出力(イベント本体バイト列)を FodprEvent へ復元する (Nim の decodeEvent 相当)。
     * PUSH パケットの「イベント本体」部分を渡すことを想定している。
     */
    public static decodeEvent(data: Uint8Array): FodprEvent {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
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
        const decoder = new TextDecoder();
        const tags: string[] = [];
        for (let i = 0; i < tagCount; i++) {
            const tLen = view.getUint16(offset, false);
            offset += 2;
            tags.push(decoder.decode(data.subarray(offset, offset + tLen)));
            offset += tLen;
        }

        // content(長さ uint32 + 本体)。Uint8Array として保持 (バイナリ対応)
        const contentLen = view.getUint32(offset, false);
        offset += 4;
        const content = data.slice(offset, offset + contentLen);
        offset += contentLen;

        // signature(compact 形式 64 バイト)
        const signature = data.slice(offset, offset + 64);

        return { transType, createdAt, pubkey, tags, content, signature };
    }

    /**
     * シグナリングメッセージの署名対象バイト列をエンコードする (Nim の encodeSignalSignedData 相当)。
     * レイアウト: signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content
     */
    public static encodeSignalSignedData(s: FodprSignal): Uint8Array {
        const encoder = new TextEncoder();
        const contentBytes = encoder.encode(s.content);

        const totalLen = 1 + 33 + 33 + 4 + contentBytes.length;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // signalType (1 バイト)
        view.setUint8(offset, s.signalType);
        offset += 1;

        // senderPubkey (圧縮形式 33 バイト)
        if (s.sender.length !== 33) {
            throw new Error(`Invalid sender pubkey length: expected 33, got ${s.sender.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(s.sender);
        offset += 33;

        // targetPubkey (圧縮形式 33 バイト)
        if (s.target.length !== 33) {
            throw new Error(`Invalid target pubkey length: expected 33, got ${s.target.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(s.target);
        offset += 33;

        // content (長さ uint32, ビッグエンディアン)
        view.setUint32(offset, contentBytes.length, false);
        offset += 4;
        new Uint8Array(buffer, offset, contentBytes.length).set(contentBytes);
        offset += contentBytes.length;

        return new Uint8Array(buffer);
    }

    /**
     * シグナリングメッセージをワイヤ形式にエンコードする (Nim の encodeSignal 相当)。
     * レイアウト: encodeSignalSignedData の結果に signature(64) を連結する。
     * (MsgTypeSignal の msgType バイトは含めない。呼び出し側が付与する。)
     */
    public static encodeSignal(s: FodprSignal): Uint8Array {
        const signedData = Protocol.encodeSignalSignedData(s);
        if (s.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${s.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(s.signature, signedData.length);
        return buffer;
    }

    /**
     * ストリームからシグナリングメッセージ本体を復元する (Nim の decodeSignal 相当)。
     * msgType バイトは呼び出し側が読み飛ばしてから渡すこと。
     */
    public static decodeSignal(data: Uint8Array): FodprSignal {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();
        let offset = 0;

        // signalType (1 バイト)
        const signalType = view.getUint8(offset);
        offset += 1;

        // senderPubkey (圧縮形式 33 バイト)
        const sender = data.slice(offset, offset + 33);
        offset += 33;

        // targetPubkey (圧縮形式 33 バイト)
        const target = data.slice(offset, offset + 33);
        offset += 33;

        // content (長さ uint32)
        const contentLen = view.getUint32(offset, false);
        offset += 4;
        const content = decoder.decode(data.subarray(offset, offset + contentLen));
        offset += contentLen;

        // signature (compact 形式 64 バイト)
        const signature = data.slice(offset, offset + 64);

        return { signalType, sender, target, content, signature };
    }

    /**
     * 送信タイプの数値から表示用の名前を返す (ログ表示用)。
     * Nim 側の transTypeName に相当。
     */
    public static transTypeName(transType: number): string {
        switch (transType) {
            case TransTypeJSON:   return "JSON";
            case TransTypeString: return "String";
            case TransTypeBinary: return "Binary";
            case TransTypeSigned: return "Signed";
            case TransTypeEncrypted: return "Encrypted";
            case TransTypeData: return "Data";
            case TransTypePeerList: return "PeerList";
            case TransTypeWoTIntro: return "WoTIntro";
            case TransTypeInvitation: return "Invitation";
            default:              return `Unknown(${transType})`;
        }
    }

    /**
     * シグナリングメッセージの種別の数値から表示用の名前を返す (Nim の signalTypeName 相当)。
     */
    public static signalTypeName(signalType: number): string {
        switch (signalType) {
            case SignalOffer:      return "Offer";
            case SignalAnswer:     return "Answer";
            case SignalCandidate:  return "Candidate";
            default:               return `Unknown(${signalType})`;
        }
    }

    // -----------------------------------------------------------------------
    // WebRTC データチャネルメッセージ (FodprData)
    // -----------------------------------------------------------------------
    // パケット形式: senderPubkey(33) | targetPubkey(33) | seq(8) | timestamp(8) |
    //   tagCount(2) | (tagLen(2) | tag)* | contentLen(4) | content | signature(64)
    //
    // 署名対象: senderPubkey(33) | targetPubkey(33) | seq(8) | timestamp(8) |
    //   tagCount(2) | (tagLen(2) | tag)* | contentLen(4) | content

    /**
     * データメッセージの署名対象バイト列をエンコードする (Nim の encodeDataSignedData 相当)。
     */
    public static encodeDataSignedData(d: FodprData): Uint8Array {
        const encoder = new TextEncoder();

        // タグのエンコード
        let tagsBytesLen = 2;
        const encodedTags: { len: number; bytes: Uint8Array }[] = [];
        for (const tag of d.tags) {
            const b = encoder.encode(tag);
            encodedTags.push({ len: b.length, bytes: b });
            tagsBytesLen += 2 + b.length;
        }

        // 全体サイズ: senderPubkey(33) + targetPubkey(33) + seq(8) + timestamp(8) + tagsBytesLen + contentLen(4) + content
        const totalLen = 33 + 33 + 8 + 8 + tagsBytesLen + 4 + d.content.length;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // senderPubkey (33 バイト)
        if (d.sender.length !== 33) {
            throw new Error(`Invalid sender pubkey length: expected 33, got ${d.sender.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(d.sender);
        offset += 33;

        // targetPubkey (33 バイト)
        if (d.target.length !== 33) {
            throw new Error(`Invalid target pubkey length: expected 33, got ${d.target.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(d.target);
        offset += 33;

        // seq (uint64, ビッグエンディアン)
        view.setBigUint64(offset, BigInt(d.seq), false);
        offset += 8;

        // timestamp (uint64, ビッグエンディアン)
        view.setBigUint64(offset, BigInt(d.timestamp), false);
        offset += 8;

        // tagCount (uint16, ビッグエンディアン)
        view.setUint16(offset, d.tags.length, false);
        offset += 2;

        // 各タグ
        for (const t of encodedTags) {
            view.setUint16(offset, t.len, false);
            offset += 2;
            new Uint8Array(buffer, offset, t.bytes.length).set(t.bytes);
            offset += t.bytes.length;
        }

        // content (uint32 length + data)
        view.setUint32(offset, d.content.length, false);
        offset += 4;
        new Uint8Array(buffer, offset, d.content.length).set(d.content);
        offset += d.content.length;

        return new Uint8Array(buffer);
    }

    /**
     * データメッセージをワイヤ形式にエンコードする (Nim の encodeData 相当)。
     * レイアウト: encodeDataSignedData の結果に signature(64) を連結
     */
    public static encodeData(d: FodprData): Uint8Array {
        const signedData = Protocol.encodeDataSignedData(d);
        if (d.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${d.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(d.signature, signedData.length);
        return buffer;
    }

    /**
     * ストリームからデータメッセージ本体を復元する (Nim の decodeData 相当)。
     */
    public static decodeData(data: Uint8Array): FodprData {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();
        let offset = 0;

        // senderPubkey (33 バイト)
        const sender = data.slice(offset, offset + 33);
        offset += 33;

        // targetPubkey (33 バイト)
        const target = data.slice(offset, offset + 33);
        offset += 33;

        // seq (uint64)
        const seq = Number(view.getBigUint64(offset, false));
        offset += 8;

        // timestamp (uint64)
        const timestamp = Number(view.getBigUint64(offset, false));
        offset += 8;

        // tagCount (uint16)
        const tagCount = view.getUint16(offset, false);
        offset += 2;
        const tags: string[] = [];
        for (let i = 0; i < tagCount; i++) {
            const tLen = view.getUint16(offset, false);
            offset += 2;
            tags.push(decoder.decode(data.subarray(offset, offset + tLen)));
            offset += tLen;
        }

        // content (uint32 length + data)
        const contentLen = view.getUint32(offset, false);
        offset += 4;
        const content = data.slice(offset, offset + contentLen);
        offset += contentLen;

        // signature (64 バイト)
        const signature = data.slice(offset, offset + 64);

        return { sender, target, seq, timestamp, tags, content, signature };
    }

    // -----------------------------------------------------------------------
    // F2F: PeerInfo エンコード/デコード
    // -----------------------------------------------------------------------
    // PeerInfo 形式: pubkey(33) | addrCount(1) | (addrLen(2) | addr)* | lastSeen(8) | trustScore(4)

    /**
     * PeerInfo をバイナリにエンコードする (Nim の encodePeerInfo 相当)。
     */
    public static encodePeerInfo(p: PeerInfo): Uint8Array {
        const encoder = new TextEncoder();

        // アドレスのエンコード
        let addrsTotalLen = 0;
        const encodedAddrs: { len: number; bytes: Uint8Array }[] = [];
        for (const addr of p.addresses) {
            const b = encoder.encode(addr);
            encodedAddrs.push({ len: b.length, bytes: b });
            addrsTotalLen += 2 + b.length;
        }

        const totalLen = 33 + 1 + addrsTotalLen + 8 + 4;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // pubkey (33 バイト)
        if (p.pubkey.length !== 33) {
            throw new Error(`Invalid pubkey length: expected 33, got ${p.pubkey.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(p.pubkey);
        offset += 33;

        // addrCount (1 バイト)
        view.setUint8(offset, Math.min(p.addresses.length, 255));
        offset += 1;

        // 各アドレス
        for (const a of encodedAddrs) {
            view.setUint16(offset, a.len, false);
            offset += 2;
            new Uint8Array(buffer, offset, a.bytes.length).set(a.bytes);
            offset += a.bytes.length;
        }

        // lastSeen (uint64)
        view.setBigUint64(offset, BigInt(p.lastSeen), false);
        offset += 8;

        // trustScore (float32 as uint32 big-endian)
        const tsView = new DataView(new ArrayBuffer(4));
        tsView.setFloat32(0, p.trustScore);
        view.setUint32(offset, tsView.getUint32(0), false);
        offset += 4;

        return new Uint8Array(buffer);
    }

    /**
     * ストリームから PeerInfo を復元する (Nim の decodePeerInfo 相当)。
     */
    public static decodePeerInfo(data: Uint8Array): PeerInfo {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();
        let offset = 0;

        // pubkey (33 バイト)
        const pubkey = data.slice(offset, offset + 33);
        offset += 33;

        // addrCount (1 バイト)
        const addrCount = view.getUint8(offset);
        offset += 1;

        // 各アドレス
        const addresses: string[] = [];
        for (let i = 0; i < addrCount; i++) {
            const aLen = view.getUint16(offset, false);
            offset += 2;
            addresses.push(decoder.decode(data.subarray(offset, offset + aLen)));
            offset += aLen;
        }

        // lastSeen (uint64)
        const lastSeen = Number(view.getBigUint64(offset, false));
        offset += 8;

        // trustScore (float32)
        const tsUint32 = view.getUint32(offset, false);
        const tsBuffer = new ArrayBuffer(4);
        new DataView(tsBuffer).setUint32(0, tsUint32);
        const trustScore = new DataView(tsBuffer).getFloat32(0);
        offset += 4;

        return { pubkey, addresses, lastSeen, trustScore };
    }

    // -----------------------------------------------------------------------
    // F2F: PeerList エンコード/デコード
    // -----------------------------------------------------------------------
    // PeerList 形式: version(8) | peerCount(2) | PeerInfo * peerCount | signature(64)

    /**
     * PeerList の署名対象バイト列をエンコードする (Nim の encodePeerListSignedData 相当)。
     */
    public static encodePeerListSignedData(pl: PeerList): Uint8Array {
        const parts: Uint8Array[] = [];

        // version (uint64)
        const versionBuf = new ArrayBuffer(8);
        new DataView(versionBuf).setBigUint64(0, BigInt(pl.version), false);
        parts.push(new Uint8Array(versionBuf));

        // peerCount (uint16)
        const pcBuf = new ArrayBuffer(2);
        new DataView(pcBuf).setUint16(0, pl.peers.length, false);
        parts.push(new Uint8Array(pcBuf));

        // 各 PeerInfo
        for (const p of pl.peers) {
            parts.push(Protocol.encodePeerInfo(p));
        }

        const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
        const buffer = new Uint8Array(totalLen);
        let offset = 0;
        for (const part of parts) {
            buffer.set(part, offset);
            offset += part.length;
        }
        return buffer;
    }

    /**
     * PeerList をワイヤ形式にエンコードする (Nim の encodePeerList 相当)。
     */
    public static encodePeerList(pl: PeerList): Uint8Array {
        const signedData = Protocol.encodePeerListSignedData(pl);
        if (pl.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${pl.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(pl.signature, signedData.length);
        return buffer;
    }

    /**
     * ストリームから PeerList を復元する (Nim の decodePeerList 相当)。
     */
    public static decodePeerList(data: Uint8Array): PeerList {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        let offset = 0;

        // version (uint64)
        const version = Number(view.getBigUint64(offset, false));
        offset += 8;

        // peerCount (uint16)
        const peerCount = view.getUint16(offset, false);
        offset += 2;

        // 各 PeerInfo
        const peers: PeerInfo[] = [];
        let dataOffset = offset;
        for (let i = 0; i < peerCount; i++) {
            const peer = Protocol.decodePeerInfo(data.subarray(dataOffset));
            peers.push(peer);
            dataOffset += Protocol.encodePeerInfo(peer).length;
        }
        offset = dataOffset;

        // signature (64 バイト)
        const signature = data.slice(offset, offset + 64);

        return { version, peerCount, peers, signature };
    }

    /**
     * PEER_LIST_PUSH / PEER_LIST_REQ パケットをエンコードする。
     * レイアウト: MsgTypePeerListPush(1) | encodePeerList(pl)
     */
    public static encodePeerListPacket(pl: PeerList, isPush: boolean = true): Uint8Array {
        const encoded = Protocol.encodePeerList(pl);
        const msgType = isPush ? MsgTypePeerListPush : MsgTypePeerListReq;
        const buffer = new Uint8Array(1 + encoded.length);
        buffer[0] = msgType;
        buffer.set(encoded, 1);
        return buffer;
    }

    /**
     * PEER_LIST_PUSH / PEER_LIST_REQ パケットをデコードする。
     */
    public static decodePeerListPacket(data: Uint8Array): PeerList {
        const msgType = data[0];
        if (msgType !== MsgTypePeerListPush && msgType !== MsgTypePeerListReq) {
            throw new Error(`Invalid message type: expected 0x${MsgTypePeerListPush.toString(16)} or 0x${MsgTypePeerListReq.toString(16)}, got 0x${msgType.toString(16)}`);
        }
        return Protocol.decodePeerList(data.subarray(1));
    }

    // -----------------------------------------------------------------------
    // F2F: WoT紹介 (WoTIntro) エンコード/デコード
    // -----------------------------------------------------------------------
    // WoTIntro 形式: introducerPubkey(33) | PeerInfo | signature(64)

    /**
     * WoTIntro の署名対象バイト列をエンコードする (Nim の encodeWoTIntroSignedData 相当)。
     */
    public static encodeWoTIntroSignedData(wi: WoTIntro): Uint8Array {
        const peerInfoBytes = Protocol.encodePeerInfo(wi.newPeer);
        const buffer = new Uint8Array(33 + peerInfoBytes.length);
        buffer.set(wi.introducer, 0);
        buffer.set(peerInfoBytes, 33);
        return buffer;
    }

    /**
     * WoTIntro をワイヤ形式にエンコードする (Nim の encodeWoTIntro 相当)。
     */
    public static encodeWoTIntro(wi: WoTIntro): Uint8Array {
        const signedData = Protocol.encodeWoTIntroSignedData(wi);
        if (wi.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${wi.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(wi.signature, signedData.length);
        return buffer;
    }

    /**
     * ストリームから WoTIntro を復元する (Nim の decodeWoTIntro 相当)。
     */
    public static decodeWoTIntro(data: Uint8Array): WoTIntro {
        // introducerPubkey (33 バイト)
        const introducer = data.slice(0, 33);

        // newPeer (PeerInfo) - decode from offset 33
        // Since PeerInfo has variable-length fields, we decode it first,
        // then calculate the length by re-encoding
        const restData = data.subarray(33);
        const newPeer = Protocol.decodePeerInfo(restData);

        // Calculate PeerInfo length for signature offset
        const peerInfoLen = Protocol.encodePeerInfo(newPeer).length;

        // signature (64 バイト)
        const signature = data.slice(33 + peerInfoLen, 33 + peerInfoLen + 64);

        return { introducer, newPeer, signature };
    }

    /**
     * WOT_INTRO_PUSH / WOT_INTRO_REQ パケットをエンコードする。
     */
    public static encodeWoTIntroPacket(wi: WoTIntro, isPush: boolean = true): Uint8Array {
        const encoded = Protocol.encodeWoTIntro(wi);
        const msgType = isPush ? MsgTypeWoTIntroPush : MsgTypeWoTIntro;
        const buffer = new Uint8Array(1 + encoded.length);
        buffer[0] = msgType;
        buffer.set(encoded, 1);
        return buffer;
    }

    /**
     * WOT_INTRO_PUSH / WOT_INTRO_REQ パケットをデコードする。
     */
    public static decodeWoTIntroPacket(data: Uint8Array): WoTIntro {
        const msgType = data[0];
        if (msgType !== MsgTypeWoTIntroPush && msgType !== MsgTypeWoTIntro) {
            throw new Error(`Invalid message type: expected 0x${MsgTypeWoTIntroPush.toString(16)} or 0x${MsgTypeWoTIntro.toString(16)}, got 0x${msgType.toString(16)}`);
        }
        return Protocol.decodeWoTIntro(data.subarray(1));
    }

    // -----------------------------------------------------------------------
    // F2F: インビテーションコード (InvitationCode) エンコード/デコード + Bech32
    // -----------------------------------------------------------------------
    // InvitationCode (バイナリ): version(1) | issuerPubkey(33) | PeerInfo | expiresAt(8) | scope(1) | signature(64)
    // 署名対象: version(1) | issuerPubkey(33) | PeerInfo | expiresAt(8) | scope(1)
    // Bech32 エンコード HRP: "f2finv"

    /**
     * InvitationCode の署名対象バイト列をエンコードする (Nim の encodeInvitationSignedData 相当)。
     */
    public static encodeInvitationSignedData(inv: InvitationCode): Uint8Array {
        const parts: Uint8Array[] = [];

        // version (1 バイト)
        parts.push(new Uint8Array([inv.version]));

        // issuerPubkey (33 バイト)
        if (inv.issuer.length !== 33) {
            throw new Error(`Invalid issuer pubkey length: expected 33, got ${inv.issuer.length}`);
        }
        parts.push(inv.issuer);

        // targetPeer (PeerInfo)
        parts.push(Protocol.encodePeerInfo(inv.targetPeer));

        // expiresAt (uint64)
        const eaBuf = new ArrayBuffer(8);
        new DataView(eaBuf).setBigUint64(0, BigInt(inv.expiresAt), false);
        parts.push(new Uint8Array(eaBuf));

        // scope (1 バイト)
        parts.push(new Uint8Array([inv.scope]));

        const totalLen = parts.reduce((sum, p) => sum + p.length, 0);
        const buffer = new Uint8Array(totalLen);
        let offset = 0;
        for (const part of parts) {
            buffer.set(part, offset);
            offset += part.length;
        }
        return buffer;
    }

    /**
     * InvitationCode をバイナリにエンコードする (Nim の encodeInvitation 相当)。
     */
    public static encodeInvitation(inv: InvitationCode): Uint8Array {
        const signedData = Protocol.encodeInvitationSignedData(inv);
        if (inv.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${inv.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(inv.signature, signedData.length);
        return buffer;
    }

    /**
     * ストリームから InvitationCode を復元する (Nim の decodeInvitation 相当)。
     */
    public static decodeInvitation(data: Uint8Array): InvitationCode {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        let offset = 0;

        // version (1 バイト)
        const version = view.getUint8(offset);
        offset += 1;

        // issuerPubkey (33 バイト)
        const issuer = data.slice(offset, offset + 33);
        offset += 33;

        // targetPeer (PeerInfo)
        const targetPeer = Protocol.decodePeerInfo(data.subarray(offset));
        offset += Protocol.encodePeerInfo(targetPeer).length;

        // expiresAt (uint64)
        const expiresAt = Number(view.getBigUint64(offset, false));
        offset += 8;

        // scope (1 バイト)
        const scope = view.getUint8(offset);
        offset += 1;

        // signature (64 バイト)
        const signature = data.slice(offset, offset + 64);

        return { version, issuer, targetPeer, expiresAt, scope, signature };
    }

    /**
     * InvitationCode を Bech32 文字列 (f2finv1...) にエンコードする (Nim の encodeInvitationBech32 相当)。
     */
    public static encodeInvitationBech32(inv: InvitationCode): string {
        const bin = Protocol.encodeInvitation(inv);
        return CryptoUtils.bech32Encode("f2finv", bin);
    }

    /**
     * Bech32 文字列 (f2finv1...) から InvitationCode を復元する (Nim の decodeInvitationBech32 相当)。
     */
    public static decodeInvitationBech32(code: string): InvitationCode {
        const data = CryptoUtils.bech32Decode(code, "f2finv");
        return Protocol.decodeInvitation(data);
    }

    // -----------------------------------------------------------------------
    // DHT (Kademlia over WebRTC) エンコード/デコード
    // -----------------------------------------------------------------------
    // DHT メッセージは WebRTC データチャネル (FodprData) の content に格納する。
    // 形式: MsgTypeDht(0x0B) | op(1) | msgId(16) | key(32) | senderPubkey(33) |
    //       nodeCount(2) | DhtNodeInfo* | valueLen(4) | value | signature(64)
    // 署名対象: op(1) | msgId(16) | key(32) | senderPubkey(33) | nodeCount(2) |
    //          DhtNodeInfo* | valueLen(4) | value
    //
    // 応答 (MsgTypeDhtNodes=0x8B / MsgTypeDhtValue=0x8C) も同じ構造で、
    // 先頭の msgType バイトだけが異なる。

    /**
     * 公開鍵からノードIDを計算する: nodeId = SHA-256(圧縮公開鍵)。
     */
    public static nodeId(pubkey: Uint8Array): Uint8Array {
        return sha256(pubkey);
    }

    /**
     * DhtNodeInfo をバイナリにエンコードする (Nim の encodeDhtNodeInfo 相当)。
     * 形式: nodeId(32) | pubkey(33) | addrCount(1) | (addrLen(2) | addr)* | lastSeen(8) | trustScore(8)
     */
    public static encodeDhtNodeInfo(n: DhtNodeInfo): Uint8Array {
        const encoder = new TextEncoder();

        let addrsTotalLen = 0;
        const encodedAddrs: { len: number; bytes: Uint8Array }[] = [];
        for (const addr of n.addresses) {
            const b = encoder.encode(addr);
            encodedAddrs.push({ len: b.length, bytes: b });
            addrsTotalLen += 2 + b.length;
        }

        const totalLen = 32 + 33 + 1 + addrsTotalLen + 8 + 8;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        new Uint8Array(buffer, offset, 32).set(n.nodeId.subarray(0, 32));
        offset += 32;

        if (n.pubkey.length !== 33) {
            throw new Error(`Invalid DHT node pubkey length: expected 33, got ${n.pubkey.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(n.pubkey);
        offset += 33;

        view.setUint8(offset, n.addresses.length);
        offset += 1;

        for (const a of encodedAddrs) {
            view.setUint16(offset, a.len, false);
            offset += 2;
            new Uint8Array(buffer, offset, a.bytes.length).set(a.bytes);
            offset += a.bytes.length;
        }

        view.setBigUint64(offset, BigInt(n.lastSeen), false);
        offset += 8;

        // trustScore を float64 (ビッグエンディアン) で保存
        const tsBuf = new ArrayBuffer(8);
        new DataView(tsBuf).setFloat64(0, n.trustScore, false);
        new Uint8Array(buffer, offset, 8).set(new Uint8Array(tsBuf));
        offset += 8;

        return new Uint8Array(buffer);
    }

    /**
     * DhtNodeInfo をバイナリから復元する (Nim の decodeDhtNodeInfo 相当)。
     */
    public static decodeDhtNodeInfo(data: Uint8Array, offset = 0): { node: DhtNodeInfo; next: number } {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();

        const nodeId = data.slice(offset, offset + 32);
        offset += 32;

        const pubkey = data.slice(offset, offset + 33);
        offset += 33;

        const addrCount = view.getUint8(offset);
        offset += 1;
        const addresses: string[] = [];
        for (let i = 0; i < addrCount; i++) {
            const aLen = view.getUint16(offset, false);
            offset += 2;
            addresses.push(decoder.decode(data.subarray(offset, offset + aLen)));
            offset += aLen;
        }

        const lastSeen = Number(view.getBigUint64(offset, false));
        offset += 8;

        const trustScore = view.getFloat64(offset, false);
        offset += 8;

        return { node: { nodeId, pubkey, addresses, lastSeen, trustScore }, next: offset };
    }

    /**
     * DHT メッセージの署名対象バイト列をエンコードする (Nim の encodeDhtSignedData 相当)。
     */
    public static encodeDhtSignedData(m: DhtMessage): Uint8Array {
        let nodesBytesLen = 0;
        const encodedNodes: Uint8Array[] = [];
        for (const n of m.nodes) {
            const nb = Protocol.encodeDhtNodeInfo(n);
            encodedNodes.push(nb);
            nodesBytesLen += nb.length;
        }

        // op(1) + msgId(16) + key(32) + sender(33) + nodeCount(2) + nodes + valueLen(4) + value
        const totalLen = 1 + 16 + 32 + 33 + 2 + nodesBytesLen + 4 + m.value.length;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        view.setUint8(offset, m.op);
        offset += 1;

        new Uint8Array(buffer, offset, 16).set(m.msgId.subarray(0, 16));
        offset += 16;

        new Uint8Array(buffer, offset, 32).set(m.key.subarray(0, 32));
        offset += 32;

        if (m.sender.length !== 33) {
            throw new Error(`Invalid DHT sender pubkey length: expected 33, got ${m.sender.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(m.sender);
        offset += 33;

        view.setUint16(offset, m.nodes.length, false);
        offset += 2;

        for (const nb of encodedNodes) {
            new Uint8Array(buffer, offset, nb.length).set(nb);
            offset += nb.length;
        }

        view.setUint32(offset, m.value.length, false);
        offset += 4;
        new Uint8Array(buffer, offset, m.value.length).set(m.value);
        offset += m.value.length;

        return new Uint8Array(buffer);
    }

    /**
     * DHT メッセージをワイヤ形式にエンコードする (Nim の encodeDht 相当)。
     * レイアウト: encodeDhtSignedData の結果に signature(64) を連結する。
     * (msgType バイトは含めない。呼び出し側が付与する。)
     */
    public static encodeDht(m: DhtMessage): Uint8Array {
        const signedData = Protocol.encodeDhtSignedData(m);
        if (m.signature.length !== 64) {
            throw new Error(`Invalid DHT signature length: expected 64, got ${m.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(m.signature, signedData.length);
        return buffer;
    }

    /**
     * DHT メッセージをバイナリから復元する (Nim の decodeDht 相当)。
     * (msgType バイトは読み飛ばしてから渡すこと。)
     */
    public static decodeDht(data: Uint8Array): DhtMessage {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        let offset = 0;

        const op = view.getUint8(offset);
        offset += 1;

        const msgId = data.slice(offset, offset + 16);
        offset += 16;

        const key = data.slice(offset, offset + 32);
        offset += 32;

        const sender = data.slice(offset, offset + 33);
        offset += 33;

        const nodeCount = view.getUint16(offset, false);
        offset += 2;

        const nodes: DhtNodeInfo[] = [];
        for (let i = 0; i < nodeCount; i++) {
            const r = Protocol.decodeDhtNodeInfo(data, offset);
            nodes.push(r.node);
            offset = r.next;
        }

        const valueLen = view.getUint32(offset, false);
        offset += 4;
        const value = data.slice(offset, offset + valueLen);
        offset += valueLen;

        const signature = data.slice(offset, offset + 64);

        return { op, msgId, key, nodes, value, sender, signature };
    }

    /**
     * DHT 操作の数値から表示用の名前を返す (Nim の dhtOpName 相当)。
     */
    public static dhtOpName(op: number): string {
        switch (op) {
            case DhtOpPing:      return "Ping";
            case DhtOpPong:      return "Pong";
            case DhtOpFindNode:  return "FindNode";
            case DhtOpFindValue: return "FindValue";
            case DhtOpStore:     return "Store";
            default:             return `Unknown(${op})`;
        }
    }

    // -----------------------------------------------------------------------
    // F2F: シードレスポンス (JSON Text フレーム)
    // -----------------------------------------------------------------------
    // シードレスポンスは JSON テキストフレームで送信される。
    // { type: "seed_response", version: uint64, nodes: [{pubkey: hex, addresses: [...]}], signature: base64 }

    /**
     * シードレスポンス JSON をエンコードする (Nim の handleSeedRequest 相当のレスポンス生成)。
     * @param version バージョン (uint64)
     * @param nodes ノードリスト
     * @param signatureHex 署名 (HEX)
     * @returns JSON 文字列
     */
    public static encodeSeedResponse(version: number, nodes: SeedNode[], signatureHex: string): string {
        const nodeObjs = nodes.map(n => ({
            pubkey: bytesToHex(n.pubkey),
            addresses: n.addresses,
        }));
        return JSON.stringify({
            type: "seed_response",
            version: version,
            nodes: nodeObjs,
            signature: signatureHex,
        });
    }

    /**
     * シードリクエスト JSON をエンコードする。
     * @param maxNodes 最大ノード数
     * @returns JSON 文字列
     */
    public static encodeSeedRequest(maxNodes: number = 50): string {
        return JSON.stringify({
            type: "seed_request",
            max_nodes: maxNodes,
        });
    }

    /**
     * シードレスポンス JSON をデコードする。
     * @param json Text フレームの JSON 文字列
     * @returns SeedResponse
     */
    public static decodeSeedResponse(json: string): SeedResponse {
        const doc = JSON.parse(json);
        if (doc.type !== "seed_response") {
            throw new Error(`Invalid seed response type: ${doc.type}`);
        }
        const nodes: SeedNode[] = doc.nodes.map((n: any) => ({
            pubkey: CryptoUtils.hexToBytes(n.pubkey),
            addresses: n.addresses,
        }));
        // signature is base64 encoded
        const signature = CryptoUtils.base64Decode(doc.signature);
        return {
            type: "seed_response",
            version: Number(doc.version),
            nodes,
            signature,
        };
    }
}