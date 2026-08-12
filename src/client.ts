/**
 * FodprClient
 * ----------
 * Fodpr リレーサーバー(ws://...:8000/ で待ち受けるサーバー)へ接続し、
 * イベント投稿(EVENT)と購読要求(REQ)を行う WebSocket クライアント。
 *
 * 通信はすべて「バイナリフレーム」で行う。
 * テキストフレームは UTF-8 エンコードされるため、公開鍵や署名など
 * 0x80 以上の任意バイト列を含むデータはそのまま運べない(文字化けする)。
 * そのため Fodpr のプロトコルデータは必ずバイナリで送受信する。
 *
 * パケット構造(いずれも先頭 1 バイトがメッセージ種別):
 *   EVENT: [0x01] + encodeEvent() の結果
 *   REQ  : encodeReq() の結果(先頭に 0x02 を含む)
 *   DEL  : encodeDel() の結果(先頭に 0x03 を含む)
 *   AUTH : encodeAuth() の結果(先頭に 0x04 を含む)
 *   SIGNAL : [0x05] + encodeSignal() の結果
 *   PUSH : [0x81] + [SubIdLen(2)] + [SubId] + encodeEvent() の結果
 *   CHALLENGE : [0x82] + [nonce(32)]
 *   SIGNAL_PUSH : [0x83] + [SubIdLen(2)] + [SubId] + encodeSignal() の結果
 *
 * 利用例:
 *   const client = new FodprClient("ws://localhost:8000/");
 *   await client.connect();
 *   client.onEvent((subId, event) => console.log(subId, event.content));
 *   client.sendEvent({ ... });
 *   client.sendReq({ subId: "sub1", transType: TransTypeString, tagKey: "", tagVal: "" });
 */

import WebSocket from 'ws';
import {
    MsgTypeEvent, MsgTypeReq, MsgTypeDel, MsgTypeAuth, MsgTypeSignal,
    MsgTypePush, MsgTypeChallenge, MsgTypeSignalPush,
    FodprEvent, FodprReq, FodprDelReq, FodprAuth, FodprChallenge, FodprSignal,
    Protocol
} from './protocol';
import { CryptoUtils } from './crypto';

// クライアントの生成オプション
export interface FodprClientOptions {
    // true にすると接続・送信などの内部動作をコンソールに出力する(デバッグ用)
    verbose?: boolean;
    // 認証用の秘密鍵 (HEX 文字列または Uint8Array)。to: タグ付き REQ には必須。
    privateKey?: string | Uint8Array;
}

// PUSH イベントを受信したときのコールバック: (subId, event) => void
type EventHandler = (subId: string, event: FodprEvent) => void;
// テキスト応答("OK: ..." / "ERR: ..." / "EOE: ..." / "HOST_CHANGE: ...")を受信したときのコールバック
type TextHandler = (message: string) => void;
// シグナリングメッセージを受信したときのコールバック
type SignalHandler = (subId: string, signal: FodprSignal) => void;
// チャレンジを受信したときのコールバック (認証が必要な場合)
type ChallengeHandler = (challenge: FodprChallenge) => void;

export class FodprClient {
    private ws: WebSocket | null = null;
    private url: string;
    private verbose: boolean;
    private privateKey: Uint8Array | null;

    // PUSH(イベント配信)を受信したときに呼ばれるコールバック
    private eventHandler: EventHandler = () => {};
    // "OK: ..." や "ERR: ..." などのテキスト応答を受信したときに呼ばれるコールバック
    private textHandler: TextHandler = () => {};
    // シグナリングメッセージを受信したときに呼ばれるコールバック
    private signalHandler: SignalHandler = () => {};

    constructor(url: string = "ws://localhost:8000/", options: FodprClientOptions = {}) {
        this.url = url;
        this.verbose = options.verbose ?? false;
        this.privateKey = options.privateKey
            ? (typeof options.privateKey === 'string'
                ? CryptoUtils.hexToBytes(options.privateKey)
                : options.privateKey)
            : null;
    }

    // 内部デバッグログのヘルパー(verbose オプションが有効なときだけ出力)
    private log(...args: unknown[]) {
        if (this.verbose) {
            console.log(...args);
        }
    }

    // サーバーへ接続する。接続が確立したら resolve される Promise を返す。
    public connect(): Promise<void> {
        return new Promise((resolve, reject) => {
            this.ws = new WebSocket(this.url);

            this.ws.on('open', () => {
                this.log("[接続] リレーサーバーに接続しました");
                resolve();
            });

            this.ws.on('error', (error) => {
                this.log("[エラー] WebSocketエラー:", error);
                reject(error);
            });

            this.ws.on('close', (code, reason) => {
                this.log(`[切断] サーバーとの接続が切れました(コード: ${code}, 理由: ${reason.toString()})`);
            });

            this.ws.on('message', (data: WebSocket.RawData) => {
                this.handleMessage(data);
            });
        });
    }

    // PUSH イベントを受信したときに呼ばれるコールバックを登録する。
    public onEvent(callback: EventHandler) {
        this.eventHandler = callback;
    }

    // シグナリングメッセージを受信したときに呼ばれるコールバックを登録する。
    public onSignal(callback: SignalHandler) {
        this.signalHandler = callback;
    }

    // サーバーからのテキスト応答("OK: ..." / "ERR: ..." / "EOE: ...")を受信したときの
    // コールバックを登録する。
    public onText(callback: TextHandler) {
        this.textHandler = callback;
    }

    // 受信メッセージの振り分け処理。
    // サーバーは人間が読めるテキスト応答と、バイナリの PUSH / CHALLENGE / SIGNAL_PUSH パケットを混在で送ってくる。
    private handleMessage(data: WebSocket.RawData) {
        let buf: Buffer;

        // ws ライブラリはフレーム種別によって string / Buffer / Buffer[] を返す。
        if (typeof data === 'string') {
            buf = Buffer.from(data, 'utf8');
        } else if (Array.isArray(data)) {
            buf = Buffer.concat(data);
        } else if (Buffer.isBuffer(data)) {
            buf = data;
        } else {
            buf = Buffer.from(data as ArrayBuffer);
        }

        const bytes = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
        if (bytes.length === 0) {
            return;
        }

        // 先頭バイトでメッセージ種別を判別
        const msgType = bytes[0];

        switch (msgType) {
            case MsgTypePush:
                // PUSH パケット: [MsgTypePush(1)] [SubIdLen(2)] [SubId] [encodedEvent]
                {
                    const { subId, event } = Protocol.decodePush(bytes);
                    this.log(`[受信] PUSH Event [SubId: ${subId}] TransType: ${Protocol.transTypeName(event.transType)}`);
                    this.eventHandler(subId, event);
                }
                break;

            case MsgTypeChallenge:
                // CHALLENGE パケット: [MsgTypeChallenge(1)] [nonce(32)]
                {
                    const nonce = bytes.slice(1, 33);
                    const challenge: FodprChallenge = { nonce };
                    this.log("[受信] CHALLENGE (認証が必要です)");
                    this.textHandler("CHALLENGE: Authentication required");
                    // 自動認証: privateKey が設定されていれば AUTH を送信する
                    if (this.privateKey) {
                        this.sendAuth(challenge).catch(e => {
                            this.log("[エラー] AUTH 送信失敗:", e);
                            this.textHandler(`ERR: Auth failed - ${e instanceof Error ? e.message : String(e)}`);
                        });
                    }
                }
                break;

            case MsgTypeSignalPush:
                // SIGNAL_PUSH パケット: [MsgTypeSignalPush(1)] [SubIdLen(2)] [SubId] [encodedSignal]
                {
                    const { subId, signal } = Protocol.decodeSignalPush(bytes);
                    this.log(`[受信] SIGNAL_PUSH [SubId: ${subId}] signalType: ${Protocol.signalTypeName(signal.signalType)}`);
                    this.signalHandler(subId, signal);
                }
                break;

            default:
                // それ以外はテキスト応答として扱う
                {
                    const text = buf.toString('utf8');
                    this.log("[受信]:", text);
                    this.textHandler(text);
                }
                break;
        }
    }

    /**
     * イベント投稿 (EVENT)
     * サーバー側で署名検証 → 保存される。transType によって JSON / String / Binary / Signed / Encrypted を切り替える。
     */
    public sendEvent(event: FodprEvent) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error("WebSocketが接続されていません");
        }

        // イベント本体をエンコードし、先頭にメッセージ種別 EVENT(0x01) を付与する
        const payload = Protocol.encodeEvent(event);
        const buffer = new Uint8Array(1 + payload.length);
        buffer[0] = MsgTypeEvent;
        buffer.set(payload, 1);

        // バイナリフレームで送信する(バイト列がそのままサーバーに届く)
        this.ws.send(Buffer.from(buffer));
        this.log("[送信] EVENT パケットを送信しました");
    }

    /**
     * 購読要求 (REQ)
     * 指定した transType(とタグ条件)に一致する保存済みイベントをサーバーが PUSH で返してくる。
     */
    public sendReq(req: FodprReq) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error("WebSocketが接続されていません");
        }

        // encodeReq は先頭にメッセージ種別 REQ(0x02) を含むため、そのまま送るだけでよい
        const payload = Protocol.encodeReq(req);
        this.ws.send(Buffer.from(payload));
        this.log(`[送信] REQ パケット送信[SubId: ${req.subId}, TransType: ${Protocol.transTypeName(req.transType)}]`);
    }

    /**
     * イベント削除 (DEL)
     * 署名済みの削除要求をサーバーに送信する。自分の公開鍵のイベントのみ削除可能。
     */
    public sendDel(delReq: FodprDelReq) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error("WebSocketが接続されていません");
        }

        const payload = Protocol.encodeDel(delReq);
        this.ws.send(Buffer.from(payload));
        this.log(`[送信] DEL パケットを送信しました (targetType: ${Protocol.delTargetTypeName(delReq.targetType)})`);
    }

    /**
     * 認証応答 (AUTH) を送信する。
     * チャレンジ nonce に対して署名して返す (NIP-42 相当)。
     * privateKey が設定されていれば、受信した CHALLENGE に自動で応答する。
     */
    public async sendAuth(challenge: FodprChallenge): Promise<void> {
        if (!this.privateKey) {
            throw new Error("秘密鍵が設定されていません (AUTH には privateKey オプションが必要です)");
        }

        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error("WebSocketが接続されていません");
        }

        const pubkey = CryptoUtils.getRawCompressedPublicKey(this.privateKey);
        const auth: FodprAuth = {
            nonce: challenge.nonce,
            pubkey: pubkey,
            signature: new Uint8Array(64), // placeholder, will be filled
        };

        // 署名対象: nonce(32) | pubkey(33)
        const signedData = Protocol.encodeAuthSignedData(auth);
        const sigHex = await CryptoUtils.signMessage(this.privateKey, signedData);
        auth.signature = CryptoUtils.hexToBytes(sigHex);

        const payload = Protocol.encodeAuth(auth);
        this.ws.send(Buffer.from(payload));
        this.log("[送信] AUTH パケットを送信しました");
    }

    /**
     * WebRTC シグナリングメッセージ (SIGNAL) を送信する。
     * TransTypeWebRTC 専用。リレーは署名検証後に宛先の認証済み購読者へ中継する (保存しない)。
     */
    public sendSignal(signal: FodprSignal) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error("WebSocketが接続されていません");
        }

        // 先頭にメッセージ種別 SIGNAL(0x05) を付与
        const payload = Protocol.encodeSignal(signal);
        const buffer = new Uint8Array(1 + payload.length);
        buffer[0] = MsgTypeSignal;
        buffer.set(payload, 1);

        this.ws.send(Buffer.from(buffer));
        this.log(`[送信] SIGNAL パケットを送信しました (signalType: ${Protocol.signalTypeName(signal.signalType)})`);
    }

    // 接続を閉じる
    public close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}
