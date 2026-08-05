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
 *   クライアント -> サーバー: EVENT(0x01) / REQ(0x02) をバイナリフレームで送信
 *   サーバー   -> クライアント: PUSH(0x81) でイベント配信
 */

// WebSocket クライアント(FodprClient)
export { FodprClient } from './client';

// 鍵生成・署名・署名検証ユーティリティ(CryptoUtils)
export { CryptoUtils } from './crypto';

// ワイヤプロトコルのエンコード / デコード(`Protocol`)、
// メッセージ種別定数と送信タイプ(TransType)定数
export { Protocol, MsgTypeEvent, MsgTypeReq, MsgTypePush, TransTypeAll, TransTypeJSON, TransTypeString, TransTypeBinary } from './protocol';

// 公開型定義(FodprEvent / FodprReq)
export type { FodprEvent, FodprReq } from './protocol';
