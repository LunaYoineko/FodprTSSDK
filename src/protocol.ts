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
export const MsgTypeEvent = 0x01;       // イベント投稿 (クライアント -> サーバー)
export const MsgTypeReq = 0x02;         // 購読要求 (クライアント -> サーバー)
export const MsgTypeDel = 0x03;         // イベント削除要求 (クライアント -> サーバー)
export const MsgTypeAuth = 0x04;        // 認証応答 (クライアント -> サーバー, NIP-42 相当)
export const MsgTypeSignal = 0x05;      // シグナリングメッセージ (クライアント -> サーバー, WebRTC 専用)
export const MsgTypeData = 0x06;        // WebRTCデータチャネルメッセージ (P2P直接, 署名付き)
export const MsgTypePeerListReq = 0x07; // F2F: ピアリスト要求 (クライアント -> ピア)
export const MsgTypeWoTIntro = 0x08;    // F2F: WoT紹介 (クライアント -> ピア)
export const MsgTypeInvitationReq = 0x09; // F2F: インビテーション要求 (クライアント -> ピア)
export const MsgTypeGroupReq = 0x0A;    // F2F: グループ管理要求 (クライアント -> ピア/ホスト)
export const MsgTypePush = 0x81;        // イベント配信 (サーバー -> クライアント)
export const MsgTypeChallenge = 0x82;   // 認証チャレンジ (サーバー -> クライアント)
export const MsgTypeSignalPush = 0x83;  // シグナリング配信 (サーバー -> クライアント, WebRTC 専用)
export const MsgTypeDataPush = 0x84;    // WebRTCデータ配信 (リレー経由の場合)
export const MsgTypePeerListPush = 0x87; // F2F: ピアリスト配信 (ピア -> クライアント)
export const MsgTypeWoTIntroPush = 0x88; // F2F: WoT紹介配信 (ピア -> クライアント)
export const MsgTypeInvitationPush = 0x89; // F2F: インビテーション配信 (ピア -> クライアント)
export const MsgTypeGroupPush = 0x8A;   // F2F: グループ管理配信 (ホスト/ピア -> クライアント)

// 削除対象タイプ (DEL)。
// Nim 側 protocol.nim の DelTargetPubkey / DelTargetEvent / DelTargetEventId と一致。
export const DelTargetPubkey = 0;   // 公開鍵単位で削除(その送信者のイベントを全削除)
export const DelTargetEvent = 1;    // 特定イベントを削除(createdAt + content ハッシュで特定)
export const DelTargetEventId = 2;  // 特定イベントを削除(eventId で特定)

// 送信タイプ (TransType)。
// イベントの `content` がどのようなデータであるかを表し、配信方法を切り替える。
// Nim 側の TransTypeAll / TransTypeJSON / TransTypeString / TransTypeBinary /
// TransTypeSigned / TransTypeEncrypted / TransTypeWebRTC / TransTypeData /
// TransTypeF2FSignal / TransTypePeerList / TransTypeWoTIntro /
// TransTypeInvitation / TransTypeGroup と一致。
export const TransTypeAll = 0x00;      // すべてのタイプを購読する(REQ でのみ使用)
export const TransTypeJSON = 0x01;     // content は UTF-8 の JSON(サーバーが構文検証する)
export const TransTypeString = 0x02;   // content は UTF-8 の文字列
export const TransTypeBinary = 0x03;   // content は任意のバイト列(バイナリのまま配信)
export const TransTypeSigned = 0x04;   // 拡張イベント(全体署名)。createdAt / pubkey / tags を含む全フィールドに署名する
export const TransTypeEncrypted = 0x05; // 暗号化イベント。content は envelope.nim のエンベロープ
export const TransTypeWebRTC = 0x06;   // WebRTC シグナリング専用
export const TransTypeData = 0x07;     // WebRTCデータチャネル専用。P2P直接通信で使用。各メッセージに署名を付与する
export const TransTypeF2FSignal = 0x08;  // F2F: P2P直接シグナリング専用
export const TransTypePeerList = 0x09;   // F2F: ピアリスト交換 (WoTキャッシュ同期) 専用
export const TransTypeWoTIntro = 0x0A;   // F2F: WoT紹介メッセージ専用
export const TransTypeInvitation = 0x0B; // F2F: インビテーションコード専用
export const TransTypeGroup = 0x0C;      // F2F: グループ管理専用

// シグナリングメッセージの種別 (SignalType)。
// Nim 側 protocol.nim の SignalOffer / SignalAnswer / SignalCandidate / SignalHostChange と一致。
export const SignalOffer = 1;        // SDP Offer (IPv6 一時アドレスを含む候補)
export const SignalAnswer = 2;       // SDP Answer
export const SignalCandidate = 3;    // ICE Candidate (IPv6 一時アドレスを含む)
export const SignalHostChange = 4;   // ホスト変更通知 (content は JSON: {"newHost":"<fpub>", "groupId":"<groupId>"})
export const SignalGroupJoin = 5;    // グループ参加要求 (content は JSON: {"groupId":"<groupId>"})
export const SignalGroupLeave = 6;   // グループ脱退通知 (content は JSON: {"groupId":"<groupId>"})

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

// 購読 (REQ) 要求。
// transType が TransTypeAll(0) の場合はすべてのタイプを購読する。
// tagKey/tagVal でタグの絞り込みも可能。
export interface FodprReq {
    subId: string;    // 購読を識別するための ID
    transType: number; // 購読したい送信タイプ(0 = すべて)
    tagKey: string;   // 絞り込み対象のタグキー(空文字なら無条件)
    tagVal: string;   // 絞り込み対象のタグ値(空文字なら無条件)
}

// イベント削除 (DEL) 要求。
// 署名は「transType | targetType | pubkey(33)」を SHA-256 したダイジェストに対して
// 行い、署名対象に createdAt / contentHash を含めるのは DelTargetEvent のとき、
// eventId を含めるのは DelTargetEventId のとき。
export interface FodprDelReq {
    transType: number;            // 削除対象の送信タイプ
    targetType: number;           // DelTargetPubkey / DelTargetEvent / DelTargetEventId
    pubkey: Uint8Array;           // 削除対象(自分の)公開鍵(圧縮形式 33 バイト)
    createdAt: number;            // DelTargetEvent のときのみ有効(Unix タイムスタンプ秒)
    contentHash: Uint8Array;      // DelTargetEvent のときのみ有効(content の SHA-256、32 バイト)
    eventId: Uint8Array;          // DelTargetEventId のときのみ有効(イベントID 32 バイト)
    signature: Uint8Array;        // ECDSA 署名(compact 形式 64 バイト)
}

// 認証 (AUTH) 応答。NIP-42 相当の読取認証。
// サーバーから送られたチャレンジ nonce に署名して返す。
// 署名対象バイト列: nonce(32) | pubkey(33)
export interface FodprAuth {
    nonce: Uint8Array;            // サーバーから受け取ったチャレンジ nonce (32 バイト)
    pubkey: Uint8Array;           // 認証する公開鍵 (圧縮形式 33 バイト)
    signature: Uint8Array;        // nonce(32) | pubkey(33) に対する署名 (64 バイト)
}

// 認証チャレンジ (サーバー → クライアント)
export interface FodprChallenge {
    nonce: Uint8Array;            // 32 バイトのチャレンジ nonce
}

// WebRTC シグナリングメッセージ (TransTypeWebRTC 用)。
// リレーは content を解釈せず、署名検証後に宛先 (target) の認証済み購読者へ
// 即座に中継する (保存はしない)。
export interface FodprSignal {
    signalType: number;           // SignalOffer / SignalAnswer / SignalCandidate / SignalHostChange
    sender: Uint8Array;           // 送信者の公開鍵 (圧縮形式 33 バイト)
    target: Uint8Array;           // 宛先の公開鍵 (認証済み subscriber の fpub と一致)
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

// F2F: P2P直接シグナリングメッセージ (TransTypeF2FSignal 用)。
// リレーを介さず、確立済みP2Pデータチャネル経由で直接シグナリングを行う。
// 既存の FodprSignal (TransTypeWebRTC) はシード/リレー経由用として残す。
export interface F2FSignal {
    signalType: number;           // SignalOffer / SignalAnswer / SignalCandidate
    sender: Uint8Array;           // 送信者の公開鍵 (圧縮形式 33 バイト)
    target: Uint8Array;           // 宛先の公開鍵
    content: string;              // SDP JSON / ICE candidate JSON (IPv6 一時アドレス含む)
    signature: Uint8Array;        // 上記フィールド全体の ECDSA 署名 (64 バイト)
    viaRelay: boolean;            // false = 直接P2P, true = リレー経由 (互換用)
}

// F2F: ピア情報 (ピアキャッシュ・WoT用)
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

// F2F: グループメンバー情報
export interface GroupMember {
    pubkey: Uint8Array;          // メンバーの公開鍵 (圧縮形式 33 バイト)
    addresses: string[];         // 接続アドレス
    joinedAt: number;            // 参加時刻 (Unix秒, uint64)
    isHost: boolean;             // ホストかどうか
    isConnected: boolean;        // 現在接続中かどうか
}

// F2F: グループ情報 (ホスト-ゲスト星形トポロジ)
// TransTypeGroup (12) で使用
export interface F2FGroup {
    groupId: string;              // グループID (ホストのfpubを使用)
    hostPubkey: Uint8Array;       // 現在のホストの公開鍵 (圧縮形式 33 バイト)
    members: GroupMember[];       // メンバーリスト
    version: number;              // グループバージョン (uint64)
    createdAt: number;            // 作成時刻 (Unix秒, uint64)
    signature: Uint8Array;        // ホストの署名 (64 バイト)
}

// F2F: グループ参加要求 (SignalGroupJoin 用)
export interface GroupJoinReq {
    groupId: string;              // 参加したいグループID
    member: GroupMember;          // 参加するメンバー情報
    signature: Uint8Array;        // 参加者の署名 (64 バイト)
}

// F2F: グループ脱退通知 (SignalGroupLeave 用)
export interface GroupLeaveReq {
    groupId: string;              // 脱退するグループID
    memberPubkey: Uint8Array;     // 脱退するメンバーの公開鍵 (圧縮形式 33 バイト)
    signature: Uint8Array;        // 脱退者の署名 (64 バイト)
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
     * 購読要求(REQ)をバイナリにエンコードする (Nim の encodeReq 相当)。
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
     * encodeReq とは逆に、ストリームから購読要求を復元する (Nim の decodeReq 相当)。
     * メッセージ種別バイトは既に読み飛ばして渡すこと。
     */
    public static decodeReq(data: Uint8Array): FodprReq {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();
        let offset = 0;

        // subId(長さ uint16)
        const idLen = view.getUint16(offset, false);
        offset += 2;
        const subId = decoder.decode(data.subarray(offset, offset + idLen));
        offset += idLen;

        // transType (uint16)
        const transType = view.getUint16(offset, false);
        offset += 2;

        // tagKey(長さ uint16)
        const tkLen = view.getUint16(offset, false);
        offset += 2;
        const tagKey = decoder.decode(data.subarray(offset, offset + tkLen));
        offset += tkLen;

        // tagVal(長さ uint16)
        const tvLen = view.getUint16(offset, false);
        offset += 2;
        const tagVal = decoder.decode(data.subarray(offset, offset + tvLen));
        offset += tvLen;

        return { subId, transType, tagKey, tagVal };
    }

    /**
     * 削除要求の署名対象バイト列を生成する (Nim の encodeDelSignedData 相当)。
     *
     * レイアウト(すべてビッグエンディアン):
     *   transType(2) | targetType(1) | pubkey(33) |
     *   [createdAt(8) | contentHash(32)]   ← DelTargetEvent のときのみ
     *   [eventId(32)]                      ← DelTargetEventId のときのみ
     *
     * クライアント側とサーバー側で完全に一致させる必要がある。
     */
    public static encodeDelSignedData(req: FodprDelReq): Uint8Array {
        const hasEvent = req.targetType === DelTargetEvent;
        const hasEventId = req.targetType === DelTargetEventId;
        const totalLen = 2 + 1 + 33 + (hasEvent ? 8 + 32 : 0) + (hasEventId ? 32 : 0);
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // transType (uint16, ビッグエンディアン)
        view.setUint16(offset, req.transType, false);
        offset += 2;

        // targetType (1 バイト)
        view.setUint8(offset, req.targetType);
        offset += 1;

        // pubkey(圧縮形式 33 バイト)
        if (req.pubkey.length !== 33) {
            throw new Error(`Invalid pubkey length: expected 33, got ${req.pubkey.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(req.pubkey);
        offset += 33;

        if (hasEvent) {
            // createdAt (uint64, ビッグエンディアン)
            view.setBigUint64(offset, BigInt(req.createdAt), false);
            offset += 8;

            // contentHash (32 バイト)
            if (req.contentHash.length !== 32) {
                throw new Error(`Invalid contentHash length: expected 32, got ${req.contentHash.length}`);
            }
            new Uint8Array(buffer, offset, 32).set(req.contentHash);
            offset += 32;
        }

        if (hasEventId) {
            // eventId (32 バイト)
            if (req.eventId.length !== 32) {
                throw new Error(`Invalid eventId length: expected 32, got ${req.eventId.length}`);
            }
            new Uint8Array(buffer, offset, 32).set(req.eventId);
            offset += 32;
        }

        return new Uint8Array(buffer);
    }

    /**
     * 削除要求全体をワイヤ形式にエンコードする (Nim の encodeDel 相当)。
     * レイアウト: MsgTypeDel(1) | encodeDelSignedData | signature(64)
     */
    public static encodeDel(req: FodprDelReq): Uint8Array {
        const signedData = Protocol.encodeDelSignedData(req);
        if (req.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${req.signature.length}`);
        }
        const totalLen = 1 + signedData.length + 64;
        const buffer = new Uint8Array(totalLen);
        buffer[0] = MsgTypeDel;
        buffer.set(signedData, 1);
        buffer.set(req.signature, 1 + signedData.length);
        return buffer;
    }

    /**
     * ストリームから削除要求を復元する (Nim の decodeDelReq 相当)。
     * メッセージ種別バイトは既に読み飛ばして渡すこと。
     */
    public static decodeDelReq(data: Uint8Array): FodprDelReq {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        let offset = 0;

        // transType (uint16, ビッグエンディアン)
        const transType = view.getUint16(offset, false);
        offset += 2;

        // targetType (1 バイト)
        const targetType = view.getUint8(offset);
        offset += 1;

        // pubkey (圧縮形式 33 バイト)
        const pubkey = data.slice(offset, offset + 33);
        offset += 33;

        let createdAt = 0;
        let contentHash = new Uint8Array(32);
        let eventId = new Uint8Array(32);

        if (targetType === DelTargetEvent) {
            createdAt = Number(view.getBigUint64(offset, false));
            offset += 8;
            contentHash = data.slice(offset, offset + 32);
            offset += 32;
        } else if (targetType === DelTargetEventId) {
            eventId = data.slice(offset, offset + 32);
            offset += 32;
        }

        // signature (compact 形式 64 バイト)
        const signature = data.slice(offset, offset + 64);

        return { transType, targetType, pubkey, createdAt, contentHash, eventId, signature };
    }

    /**
     * チャレンジパケットを生成する (Nim の encodeChallenge 相当)。
     * レイアウト: MsgTypeChallenge(1) | nonce(32)
     */
    public static encodeChallenge(nonce: Uint8Array): Uint8Array {
        if (nonce.length !== 32) {
            throw new Error(`Invalid nonce length: expected 32, got ${nonce.length}`);
        }
        const buffer = new Uint8Array(1 + 32);
        buffer[0] = MsgTypeChallenge;
        buffer.set(nonce, 1);
        return buffer;
    }

    /**
     * AUTH の署名対象バイト列 (nonce | pubkey) を作成する (Nim の encodeAuthSignedData 相当)。
     */
    public static encodeAuthSignedData(auth: FodprAuth): Uint8Array {
        if (auth.nonce.length !== 32) {
            throw new Error(`Invalid nonce length: expected 32, got ${auth.nonce.length}`);
        }
        if (auth.pubkey.length !== 33) {
            throw new Error(`Invalid pubkey length: expected 33, got ${auth.pubkey.length}`);
        }
        const buffer = new Uint8Array(32 + 33);
        buffer.set(auth.nonce, 0);
        buffer.set(auth.pubkey, 32);
        return buffer;
    }

    /**
     * 認証応答パケットをワイヤ形式にエンコードする (Nim の encodeAuth 相当)。
     * レイアウト: MsgTypeAuth(1) | nonce(32) | pubkey(33) | signature(64)
     */
    public static encodeAuth(auth: FodprAuth): Uint8Array {
        if (auth.nonce.length !== 32) {
            throw new Error(`Invalid nonce length: expected 32, got ${auth.nonce.length}`);
        }
        if (auth.pubkey.length !== 33) {
            throw new Error(`Invalid pubkey length: expected 33, got ${auth.pubkey.length}`);
        }
        if (auth.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${auth.signature.length}`);
        }
        const buffer = new Uint8Array(1 + 32 + 33 + 64);
        buffer[0] = MsgTypeAuth;
        buffer.set(auth.nonce, 1);
        buffer.set(auth.pubkey, 1 + 32);
        buffer.set(auth.signature, 1 + 32 + 33);
        return buffer;
    }

    /**
     * ストリームから認証応答を復元する (Nim の decodeAuth 相当)。
     * メッセージ種別バイトは既に読み飛ばして渡すこと。
     */
    public static decodeAuth(data: Uint8Array): FodprAuth {
        const nonce = data.slice(0, 32);
        const pubkey = data.slice(32, 65);
        const signature = data.slice(65, 129);
        return { nonce, pubkey, signature };
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
     * (MsgTypeSignal / MsgTypeSignalPush の msgType バイトは含めない。呼び出し側が付与する。)
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
     * PUSH パケットをエンコードする (Nim の broadcastEvent 相当のパケット構造)。
     * レイアウト: MsgTypePush(1) | subIdLen(2) | subId | encodedEvent
     */
    public static encodePush(subId: string, event: FodprEvent): Uint8Array {
        const encoder = new TextEncoder();
        const subIdBytes = encoder.encode(subId);
        const encodedEvent = Protocol.encodeEvent(event);

        const totalLen = 1 + 2 + subIdBytes.length + encodedEvent.length;
        const buffer = new Uint8Array(totalLen);
        const view = new DataView(buffer.buffer);

        let offset = 0;
        // MsgTypePush(1)
        view.setUint8(offset, MsgTypePush);
        offset += 1;

        // subIdLen(2) + subId
        view.setUint16(offset, subIdBytes.length, false);
        offset += 2;
        buffer.set(subIdBytes, offset);
        offset += subIdBytes.length;

        // encodedEvent
        buffer.set(encodedEvent, offset);

        return buffer;
    }

    /**
     * PUSH パケットをデコードする (Nim のクライアント側パーサー相当)。
     * レイアウト: MsgTypePush(1) | subIdLen(2) | subId | encodedEvent
     * 戻り値: { subId, event }
     */
    public static decodePush(data: Uint8Array): { subId: string; event: FodprEvent } {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();

        // メッセージ種別バイト (MsgTypePush)
        const msgType = view.getUint8(0);
        if (msgType !== MsgTypePush) {
            throw new Error(`Invalid message type for PUSH: expected 0x81, got 0x${msgType.toString(16)}`);
        }

        // subIdLen(2)
        const subIdLen = view.getUint16(1, false);
        const subId = decoder.decode(data.subarray(3, 3 + subIdLen));

        // encodedEvent
        const eventData = data.subarray(3 + subIdLen);
        const event = Protocol.decodeEvent(eventData);

        return { subId, event };
    }

    /**
     * SIGNAL_PUSH パケットをエンコードする (Nim の broadcastSignal 相当)。
     * レイアウト: MsgTypeSignalPush(1) | subIdLen(2) | subId | encodeSignal(s)
     */
    public static encodeSignalPush(subId: string, s: FodprSignal): Uint8Array {
        const encoder = new TextEncoder();
        const subIdBytes = encoder.encode(subId);
        const encodedSignal = Protocol.encodeSignal(s);

        const totalLen = 1 + 2 + subIdBytes.length + encodedSignal.length;
        const buffer = new Uint8Array(totalLen);
        const view = new DataView(buffer.buffer);

        let offset = 0;
        view.setUint8(offset, MsgTypeSignalPush);
        offset += 1;
        view.setUint16(offset, subIdBytes.length, false);
        offset += 2;
        buffer.set(subIdBytes, offset);
        offset += subIdBytes.length;
        buffer.set(encodedSignal, offset);

        return buffer;
    }

    /**
     * SIGNAL_PUSH パケットをデコードする。
     * レイアウト: MsgTypeSignalPush(1) | subIdLen(2) | subId | encodeSignal(s)
     * 戻り値: { subId, signal }
     */
    public static decodeSignalPush(data: Uint8Array): { subId: string; signal: FodprSignal } {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();

        const msgType = view.getUint8(0);
        if (msgType !== MsgTypeSignalPush) {
            throw new Error(`Invalid message type for SIGNAL_PUSH: expected 0x83, got 0x${msgType.toString(16)}`);
        }

        const subIdLen = view.getUint16(1, false);
        const subId = decoder.decode(data.subarray(3, 3 + subIdLen));

        const signalData = data.subarray(3 + subIdLen);
        const signal = Protocol.decodeSignal(signalData);

        return { subId, signal };
    }

    /**
     * SIGNAL_PUSH パケットをデコードする (F2FSignal 対応)。
     * F2FSignal は FodprSignal より末尾に viaRelay(1) バイトが余る。
     * データ長で判定し、F2FSignal ならばそれをデコードして返す。
     * FodprSignal の場合は signal フィールドのみ設定される。
     */
    public static decodeSignalPushAny(data: Uint8Array): { subId: string; signal: FodprSignal | null; f2fSignal: F2FSignal | null } {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();

        const subIdLen = view.getUint16(1, false);
        const subId = decoder.decode(data.subarray(3, 3 + subIdLen));

        const signalData = data.subarray(3 + subIdLen);

        // viaRelay バイトの有無で判定:
        // FodprSignal: signalType(1) + sender(33) + target(33) + contentLen(4) + content(CL) + signature(64)
        // F2FSignal:   signalType(1) + sender(33) + target(33) + contentLen(4) + content(CL) + viaRelay(1) + signature(64)
        // → F2FSignal は 1 バイト多い
        const minLen = 1 + 33 + 33 + 4 + 64; // = 135
        if (signalData.length < minLen) {
            throw new Error('Signal data too short');
        }

        // content length を読み出して total を計算
        const contentLen = view.getUint32(1 + 2 + subIdLen + 33 + 33, false);
        const totalWithSig = 1 + 33 + 33 + 4 + contentLen + 64;
        const totalWithViaRelay = totalWithSig + 1;

        if (signalData.length >= totalWithViaRelay) {
            // F2FSignal
            return { subId, signal: null, f2fSignal: Protocol.decodeF2FSignal(signalData) };
        } else if (signalData.length >= totalWithSig) {
            // FodprSignal
            return { subId, signal: Protocol.decodeSignal(signalData), f2fSignal: null };
        } else {
            throw new Error('Signal data length mismatch');
        }
    }

    /**
     * 送信タイプの数値から表示用の名前を返す (ログ表示用)。
     * Nim 側の transTypeName に相当。
     */
    public static transTypeName(transType: number): string {
        switch (transType) {
            case TransTypeAll:    return "All";
            case TransTypeJSON:   return "JSON";
            case TransTypeString: return "String";
            case TransTypeBinary: return "Binary";
            case TransTypeSigned: return "Signed";
            case TransTypeEncrypted: return "Encrypted";
            case TransTypeWebRTC: return "WebRTC";
            case TransTypeData: return "Data";
            case TransTypeF2FSignal: return "F2FSignal";
            case TransTypePeerList: return "PeerList";
            case TransTypeWoTIntro: return "WoTIntro";
            case TransTypeInvitation: return "Invitation";
            case TransTypeGroup: return "Group";
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
            case SignalHostChange: return "HostChange";
            case SignalGroupJoin:  return "GroupJoin";
            case SignalGroupLeave: return "GroupLeave";
            default:               return `Unknown(${signalType})`;
        }
    }

    /**
     * 削除対象タイプの数値から表示用の名前を返す。
     */
    public static delTargetTypeName(targetType: number): string {
        switch (targetType) {
            case DelTargetPubkey: return "Pubkey";
            case DelTargetEvent:  return "Event";
            case DelTargetEventId: return "EventId";
            default:              return `Unknown(${targetType})`;
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

    /**
     * DATA_PUSH パケットをエンコードする。
     * レイアウト: MsgTypeDataPush(1) | subIdLen(2) | subId | encodeData(d)
     */
    public static encodeDataPush(subId: string, d: FodprData): Uint8Array {
        const encoder = new TextEncoder();
        const subIdBytes = encoder.encode(subId);
        const encodedData = Protocol.encodeData(d);

        const totalLen = 1 + 2 + subIdBytes.length + encodedData.length;
        const buffer = new Uint8Array(totalLen);
        const view = new DataView(buffer.buffer);

        let offset = 0;
        view.setUint8(offset, MsgTypeDataPush);
        offset += 1;
        view.setUint16(offset, subIdBytes.length, false);
        offset += 2;
        buffer.set(subIdBytes, offset);
        offset += subIdBytes.length;
        buffer.set(encodedData, offset);

        return buffer;
    }

    /**
     * DATA_PUSH パケットをデコードする。
     * レイアウト: MsgTypeDataPush(1) | subIdLen(2) | subId | encodeData(d)
     */
    public static decodeDataPush(data: Uint8Array): { subId: string; dataMsg: FodprData } {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();

        const msgType = view.getUint8(0);
        if (msgType !== MsgTypeDataPush) {
            throw new Error(`Invalid message type for DATA_PUSH: expected 0x84, got 0x${msgType.toString(16)}`);
        }

        const subIdLen = view.getUint16(1, false);
        const subId = decoder.decode(data.subarray(3, 3 + subIdLen));

        const dataMsg = Protocol.decodeData(data.subarray(3 + subIdLen));

        return { subId, dataMsg };
    }

    // -----------------------------------------------------------------------
    // F2F: P2P直接シグナリング (F2FSignal)
    // -----------------------------------------------------------------------
    // パケット形式: signalType(1) | senderPubkey(33) | targetPubkey(33) |
    //   contentLen(4) | content | signature(64) | viaRelay(1)
    //
    // 署名対象: signalType(1) | senderPubkey(33) | targetPubkey(33) | contentLen(4) | content | viaRelay(1)

    /**
     * F2Fシグナリングメッセージの署名対象バイト列をエンコードする (Nim の encodeF2FSignalSignedData 相当)。
     */
    public static encodeF2FSignalSignedData(s: F2FSignal): Uint8Array {
        const encoder = new TextEncoder();
        const contentBytes = encoder.encode(s.content);

        const totalLen = 1 + 33 + 33 + 4 + contentBytes.length + 1;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // signalType (1 バイト)
        view.setUint8(offset, s.signalType);
        offset += 1;

        // senderPubkey (33 バイト)
        if (s.sender.length !== 33) {
            throw new Error(`Invalid sender pubkey length: expected 33, got ${s.sender.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(s.sender);
        offset += 33;

        // targetPubkey (33 バイト)
        if (s.target.length !== 33) {
            throw new Error(`Invalid target pubkey length: expected 33, got ${s.target.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(s.target);
        offset += 33;

        // content (uint32 length + data)
        view.setUint32(offset, contentBytes.length, false);
        offset += 4;
        new Uint8Array(buffer, offset, contentBytes.length).set(contentBytes);
        offset += contentBytes.length;

        // viaRelay (1 バイト)
        view.setUint8(offset, s.viaRelay ? 1 : 0);
        offset += 1;

        return new Uint8Array(buffer);
    }

    /**
     * F2Fシグナリングメッセージをワイヤ形式にエンコードする (Nim の encodeF2FSignal 相当)。
     */
    public static encodeF2FSignal(s: F2FSignal): Uint8Array {
        const signedData = Protocol.encodeF2FSignalSignedData(s);
        if (s.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${s.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(s.signature, signedData.length);
        return buffer;
    }

    /**
     * ストリームからF2Fシグナリングメッセージを復元する (Nim の decodeF2FSignal 相当)。
     */
    public static decodeF2FSignal(data: Uint8Array): F2FSignal {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();
        let offset = 0;

        // signalType (1 バイト)
        const signalType = view.getUint8(offset);
        offset += 1;

        // senderPubkey (33 バイト)
        const sender = data.slice(offset, offset + 33);
        offset += 33;

        // targetPubkey (33 バイト)
        const target = data.slice(offset, offset + 33);
        offset += 33;

        // content (uint32 length + data)
        const contentLen = view.getUint32(offset, false);
        offset += 4;
        const content = decoder.decode(data.subarray(offset, offset + contentLen));
        offset += contentLen;

        // viaRelay (1 バイト)
        const viaRelay = view.getUint8(offset) !== 0;
        offset += 1;

        // signature (64 バイト)
        const signature = data.slice(offset, offset + 64);

        return { signalType, sender, target, content, signature, viaRelay };
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
    // F2F: GroupMember エンコード/デコード
    // -----------------------------------------------------------------------
    // GroupMember 形式: pubkey(33) | addrCount(1) | (addrLen(2) | addr)* | joinedAt(8) | isHost(1) | isConnected(1)

    /**
     * GroupMember をバイナリにエンコードする (Nim の encodeGroupMember 相当)。
     */
    public static encodeGroupMember(m: GroupMember): Uint8Array {
        const encoder = new TextEncoder();

        // アドレスのエンコード
        const encodedAddrs: { len: number; bytes: Uint8Array }[] = [];
        let addrsTotalLen = 0;
        for (const addr of m.addresses) {
            const b = encoder.encode(addr);
            encodedAddrs.push({ len: b.length, bytes: b });
            addrsTotalLen += 2 + b.length;
        }

        const totalLen = 33 + 1 + addrsTotalLen + 8 + 1 + 1;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // pubkey (33 バイト)
        if (m.pubkey.length !== 33) {
            throw new Error(`Invalid pubkey length: expected 33, got ${m.pubkey.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(m.pubkey);
        offset += 33;

        // addrCount (1 バイト)
        view.setUint8(offset, m.addresses.length);
        offset += 1;

        // 各アドレス
        for (const a of encodedAddrs) {
            view.setUint16(offset, a.len, false);
            offset += 2;
            new Uint8Array(buffer, offset, a.bytes.length).set(a.bytes);
            offset += a.bytes.length;
        }

        // joinedAt (uint64)
        view.setBigUint64(offset, BigInt(m.joinedAt), false);
        offset += 8;

        // isHost (1 バイト)
        view.setUint8(offset, m.isHost ? 1 : 0);
        offset += 1;

        // isConnected (1 バイト)
        view.setUint8(offset, m.isConnected ? 1 : 0);

        return new Uint8Array(buffer);
    }

    /**
     * ストリームから GroupMember を復元する (Nim の decodeGroupMember 相当)。
     */
    public static decodeGroupMember(data: Uint8Array): GroupMember {
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

        // joinedAt (uint64)
        const joinedAt = Number(view.getBigUint64(offset, false));
        offset += 8;

        // isHost (1 バイト)
        const isHost = view.getUint8(offset) !== 0;
        offset += 1;

        // isConnected (1 バイト)
        const isConnected = view.getUint8(offset) !== 0;

        return { pubkey, addresses, joinedAt, isHost, isConnected };
    }

    // -----------------------------------------------------------------------
    // F2F: F2FGroup エンコード/デコード
    // -----------------------------------------------------------------------
    // F2FGroup 形式: groupIdLen(2) | groupId | hostPubkey(33) | memberCount(2) |
    //   (GroupMember)* | version(8) | createdAt(8) | signature(64)

    /**
     * F2FGroup の署名対象バイト列をエンコードする (Nim の encodeGroupSignedData 相当)。
     */
    public static encodeGroupSignedData(g: F2FGroup): Uint8Array {
        const encoder = new TextEncoder();
        const groupIdBytes = encoder.encode(g.groupId);

        const parts: Uint8Array[] = [];

        // groupIdLen(2) + groupId
        const gidLenBuf = new ArrayBuffer(2);
        new DataView(gidLenBuf).setUint16(0, groupIdBytes.length, false);
        parts.push(new Uint8Array(gidLenBuf));
        parts.push(groupIdBytes);

        // hostPubkey(33)
        parts.push(g.hostPubkey);

        // memberCount(2) + members
        const mcBuf = new ArrayBuffer(2);
        new DataView(mcBuf).setUint16(0, g.members.length, false);
        parts.push(new Uint8Array(mcBuf));
        for (const m of g.members) {
            parts.push(Protocol.encodeGroupMember(m));
        }

        // version(8)
        const vBuf = new ArrayBuffer(8);
        new DataView(vBuf).setBigUint64(0, BigInt(g.version), false);
        parts.push(new Uint8Array(vBuf));

        // createdAt(8)
        const cBuf = new ArrayBuffer(8);
        new DataView(cBuf).setBigUint64(0, BigInt(g.createdAt), false);
        parts.push(new Uint8Array(cBuf));

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
     * F2FGroup をワイヤ形式にエンコードする (Nim の encodeGroup 相当)。
     */
    public static encodeGroup(g: F2FGroup): Uint8Array {
        const signedData = Protocol.encodeGroupSignedData(g);
        if (g.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${g.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(g.signature, signedData.length);
        return buffer;
    }

    /**
     * ストリームから F2FGroup を復元する (Nim の decodeGroup 相当)。
     */
    public static decodeGroup(data: Uint8Array): F2FGroup {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();
        let offset = 0;

        // groupIdLen(2)
        const gidLen = view.getUint16(offset, false);
        offset += 2;
        const groupId = decoder.decode(data.subarray(offset, offset + gidLen));
        offset += gidLen;

        // hostPubkey(33)
        const hostPubkey = data.slice(offset, offset + 33);
        offset += 33;

        // memberCount(2)
        const memberCount = view.getUint16(offset, false);
        offset += 2;

        // 各メンバー
        const members: GroupMember[] = [];
        for (let i = 0; i < memberCount; i++) {
            const member = Protocol.decodeGroupMember(data.subarray(offset));
            members.push(member);
            offset += Protocol.encodeGroupMember(member).length;
        }

        // version(8)
        const version = Number(view.getBigUint64(offset, false));
        offset += 8;

        // createdAt(8)
        const createdAt = Number(view.getBigUint64(offset, false));
        offset += 8;

        // signature(64)
        const signature = data.slice(offset, offset + 64);

        return { groupId, hostPubkey, members, version, createdAt, signature };
    }

    // -----------------------------------------------------------------------
    // F2F: GroupJoinReq エンコード/デコード
    // -----------------------------------------------------------------------
    // GroupJoinReq 形式: groupIdLen(2) | groupId | GroupMember | signature(64)
    // 署名対象: groupIdLen(2) | groupId | encodeGroupMember(member)

    /**
     * GroupJoinReq の署名対象バイト列をエンコードする (Nim の encodeGroupJoinReqSignedData 相当)。
     */
    public static encodeGroupJoinReqSignedData(req: GroupJoinReq): Uint8Array {
        const encoder = new TextEncoder();
        const groupIdBytes = encoder.encode(req.groupId);
        const memberBytes = Protocol.encodeGroupMember(req.member);

        const totalLen = 2 + groupIdBytes.length + memberBytes.length;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // groupIdLen(2)
        view.setUint16(offset, groupIdBytes.length, false);
        offset += 2;
        new Uint8Array(buffer, offset, groupIdBytes.length).set(groupIdBytes);
        offset += groupIdBytes.length;

        // GroupMember
        new Uint8Array(buffer, offset, memberBytes.length).set(memberBytes);

        return new Uint8Array(buffer);
    }

    /**
     * GroupJoinReq をワイヤ形式にエンコードする (Nim の encodeGroupJoinReq 相当)。
     */
    public static encodeGroupJoinReq(req: GroupJoinReq): Uint8Array {
        const signedData = Protocol.encodeGroupJoinReqSignedData(req);
        if (req.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${req.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(req.signature, signedData.length);
        return buffer;
    }

    /**
     * ストリームから GroupJoinReq を復元する (Nim の decodeGroupJoinReq 相当)。
     */
    public static decodeGroupJoinReq(data: Uint8Array): GroupJoinReq {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();
        let offset = 0;

        // groupIdLen(2)
        const gidLen = view.getUint16(offset, false);
        offset += 2;
        const groupId = decoder.decode(data.subarray(offset, offset + gidLen));
        offset += gidLen;

        // GroupMember
        const member = Protocol.decodeGroupMember(data.subarray(offset));
        offset += Protocol.encodeGroupMember(member).length;

        // signature(64)
        const signature = data.slice(offset, offset + 64);

        return { groupId, member, signature };
    }

    // -----------------------------------------------------------------------
    // F2F: GroupLeaveReq エンコード/デコード
    // -----------------------------------------------------------------------
    // GroupLeaveReq 形式: groupIdLen(2) | groupId | memberPubkey(33) | signature(64)
    // 署名対象: groupIdLen(2) | groupId | memberPubkey(33)

    /**
     * GroupLeaveReq の署名対象バイト列をエンコードする (Nim の encodeGroupLeaveReqSignedData 相当)。
     */
    public static encodeGroupLeaveReqSignedData(req: GroupLeaveReq): Uint8Array {
        const encoder = new TextEncoder();
        const groupIdBytes = encoder.encode(req.groupId);

        const totalLen = 2 + groupIdBytes.length + 33;
        const buffer = new ArrayBuffer(totalLen);
        const view = new DataView(buffer);
        let offset = 0;

        // groupIdLen(2)
        view.setUint16(offset, groupIdBytes.length, false);
        offset += 2;
        new Uint8Array(buffer, offset, groupIdBytes.length).set(groupIdBytes);
        offset += groupIdBytes.length;

        // memberPubkey(33)
        if (req.memberPubkey.length !== 33) {
            throw new Error(`Invalid member pubkey length: expected 33, got ${req.memberPubkey.length}`);
        }
        new Uint8Array(buffer, offset, 33).set(req.memberPubkey);

        return new Uint8Array(buffer);
    }

    /**
     * GroupLeaveReq をワイヤ形式にエンコードする (Nim の encodeGroupLeaveReq 相当)。
     */
    public static encodeGroupLeaveReq(req: GroupLeaveReq): Uint8Array {
        const signedData = Protocol.encodeGroupLeaveReqSignedData(req);
        if (req.signature.length !== 64) {
            throw new Error(`Invalid signature length: expected 64, got ${req.signature.length}`);
        }
        const buffer = new Uint8Array(signedData.length + 64);
        buffer.set(signedData, 0);
        buffer.set(req.signature, signedData.length);
        return buffer;
    }

    /**
     * ストリームから GroupLeaveReq を復元する (Nim の decodeGroupLeaveReq 相当)。
     */
    public static decodeGroupLeaveReq(data: Uint8Array): GroupLeaveReq {
        const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
        const decoder = new TextDecoder();
        let offset = 0;

        // groupIdLen(2)
        const gidLen = view.getUint16(offset, false);
        offset += 2;
        const groupId = decoder.decode(data.subarray(offset, offset + gidLen));
        offset += gidLen;

        // memberPubkey(33)
        const memberPubkey = data.slice(offset, offset + 33);
        offset += 33;

        // signature(64)
        const signature = data.slice(offset, offset + 64);

        return { groupId, memberPubkey, signature };
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