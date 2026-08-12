/**
 * Fodpr TypeScript SDK の公開エントリーポイント。
 *
 * このモジュールは SDK が公開する API をすべて再エクスポートする。
 * ライブラリとして利用する場合は、このファイル(パッケージの main)だけを import すればよい。
 * このファイル自体には処理は書かない(副作用なし)。
 *
 * 利用例:
 *   import { CryptoUtils, Protocol } from 'fodpr-ts-sdk';
 *
 * 送受信する実データの流れ:
 *   P2P メッシュ (リレー・ホストなし):
 *     EVENT(0x01) / SIGNAL(0x05) / DATA(0x06) / PEER_LIST(0x07/0x87) /
 *     WOT_INTRO(0x08/0x88) / INVITATION(0x09/0x89) / DHT(0x0B/0x8B/0x8C)
 */

// 鍵生成・署名・署名検証ユーティリティ(CryptoUtils)
export { CryptoUtils } from './crypto';

// ワイヤプロトコルのエンコード / デコード(`Protocol`)、
// メッセージ種別定数と送信タイプ(TransType)定数
export {
    Protocol,
    // メッセージ種別
    MsgTypeEvent, MsgTypeSignal, MsgTypeData, MsgTypePeerListReq,
    MsgTypeWoTIntro, MsgTypeInvitationReq, MsgTypeDht,
    MsgTypePeerListPush, MsgTypeWoTIntroPush,
    MsgTypeInvitationPush, MsgTypeDhtNodes, MsgTypeDhtValue,
    // 送信タイプ
    TransTypeJSON, TransTypeString, TransTypeBinary,
    TransTypeSigned, TransTypeEncrypted, TransTypeData,
    TransTypePeerList, TransTypeWoTIntro, TransTypeInvitation,
    // シグナリングメッセージ種別
    SignalOffer, SignalAnswer, SignalCandidate,
    // DHT 操作種別
    DhtOpPing, DhtOpPong, DhtOpFindNode, DhtOpFindValue, DhtOpStore,
} from './protocol';

// 公開型定義
export type {
    FodprEvent, FodprSignal, FodprData,
    PeerInfo, PeerList,
    WoTIntro, InvitationCode,
    DhtNodeInfo, DhtMessage,
    SeedNode, SeedResponse,
} from './protocol';
