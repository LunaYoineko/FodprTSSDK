/**
 * Fodpr TypeScript SDK の公開エントリーポイント。
 *
 * このモジュールは SDK が公開する API をすべて再エクスポートする。
 * ライブラリとして利用する場合は、このファイル(パッケージの main)だけを import すればよい。
 * このファイル自体には処理は書かない(副作用なし)。
 *
 * 利用例:
 *   import { FodprClient, CryptoUtils, Protocol } from 'fodpr-ts-sdk';
 *
 * 送受信する実データの流れ:
 *   クライアント -> サーバー: EVENT(0x01) / REQ(0x02) / DEL(0x03) / AUTH(0x04) / SIGNAL(0x05)
 *   サーバー   -> クライアント: PUSH(0x81) / CHALLENGE(0x82) / SIGNAL_PUSH(0x83)
 */

// WebSocket クライアント(FodprClient)
export { FodprClient } from './client';
export type { FodprClientOptions } from './client';

// 鍵生成・署名・署名検証ユーティリティ(CryptoUtils)
export { CryptoUtils } from './crypto';

// ワイヤプロトコルのエンコード / デコード(`Protocol`)、
// メッセージ種別定数と送信タイプ(TransType)定数
export {
    Protocol,
    // メッセージ種別
    MsgTypeEvent, MsgTypeReq, MsgTypeDel, MsgTypeAuth, MsgTypeSignal,
    MsgTypeData, MsgTypePeerListReq, MsgTypeWoTIntro,
    MsgTypeInvitationReq, MsgTypeGroupReq,
    MsgTypePush, MsgTypeChallenge, MsgTypeSignalPush, MsgTypeDataPush,
    MsgTypePeerListPush, MsgTypeWoTIntroPush,
    MsgTypeInvitationPush, MsgTypeGroupPush,
    // 削除対象タイプ
    DelTargetPubkey, DelTargetEvent, DelTargetEventId,
    // 送信タイプ
    TransTypeAll, TransTypeJSON, TransTypeString, TransTypeBinary,
    TransTypeSigned, TransTypeEncrypted, TransTypeWebRTC,
    TransTypeData, TransTypeF2FSignal,
    TransTypePeerList, TransTypeWoTIntro, TransTypeInvitation, TransTypeGroup,
    // シグナリングメッセージ種別
    SignalOffer, SignalAnswer, SignalCandidate, SignalHostChange,
    SignalGroupJoin, SignalGroupLeave,
} from './protocol';

// 公開型定義
export type {
    FodprEvent, FodprReq, FodprDelReq, FodprAuth, FodprChallenge, FodprSignal,
    FodprData, F2FSignal,
    PeerInfo, PeerList,
    WoTIntro, InvitationCode,
    GroupMember, F2FGroup, GroupJoinReq, GroupLeaveReq,
    SeedNode, SeedResponse,
} from './protocol';
