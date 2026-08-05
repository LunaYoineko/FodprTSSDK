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
 *   PUSH : [0x81] + [SubIdLen(2)] + [SubId] + encodeEvent() の結果
 *
 * 利用例:
 *   const client = new FodprClient("ws://localhost:8000/");
 *   await client.connect();
 *   client.onEvent((subId, event) => console.log(subId, event.content));
 *   client.sendEvent({ ... });
 *   client.sendReq({ subId: "sub1", transType: TransTypeString, tagKey: "", tagVal: "" });
 */

import WebSocket from 'ws';
        import { MsgTypeEvent, MsgTypePush, FodprEvent, FodprReq, Protocol } from './protocol';

// クライアントの生成オプション
export interface FodprClientOptions {
    // true にすると接続・送信などの内部動作をコンソールに出力する(デバッグ用)
    verbose?: boolean;
}

export class FodprClient {
    private ws: WebSocket | null = null;
    private url: string;
    private verbose: boolean;

    // PUSH(イベント配信)を受信したときに呼ばれるコールバック
    private eventHandler: (subId: string, event: FodprEvent) => void = () => {};
    // "OK: ..." や "ERR: ..." などのテキスト応答を受信したときに呼ばれるコールバック
    private textHandler: (message: string) => void = () => {};

    constructor(url: string = "ws://localhost:8000/", options: FodprClientOptions = {}) {
        this.url = url;
        this.verbose = options.verbose ?? false;
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
    // callback: (subId: 購読ID, event: 受信したイベント) => void
    public onEvent(callback: (subId: string, event: FodprEvent) => void) {
        this.eventHandler = callback;
    }

    // サーバーからのテキスト応答("OK: ..." / "ERR: ..." / "EOE: ...")を受信したときの
    // コールバックを登録する。
    public onText(callback: (message: string) => void) {
        this.textHandler = callback;
    }

    // 受信メッセージの振り分け処理。
    // サーバーは人間が読めるテキスト応答と、バイナリの PUSH パケットを混在で送ってくる。
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

        // 先頭バイトが PUSH(0x81) ならバイナリのイベント配信パケット
        if (bytes[0] === MsgTypePush) {
            // レイアウト: [MsgTypePush(1)] [SubIdLen(2)] [SubId] [encodedEvent]
            const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
            const subIdLen = view.getUint16(1, false); // SubId はビッグエンディアンの uint16 長さ
            const subId = new TextDecoder().decode(bytes.subarray(3, 3 + subIdLen));
            // 残りのバイト列がイベント本体(encodeEvent の出力)
            const event = Protocol.decodeEvent(bytes.subarray(3 + subIdLen));
            this.log(`[受信] PUSH Event [SubId: ${subId}] TransType: ${Protocol.transTypeName(event.transType)}`);
            this.eventHandler(subId, event);
        } else {
            // それ以外はテキスト応答として扱う
            const text = buf.toString('utf8');
            this.log("[受信]:", text);
            this.textHandler(text);
        }
    }

    // イベント投稿 (EVENT)
    // サーバー側で署名検証 → 保存される。transType によって JSON / String / Binary を切り替える。
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

    // 購読要求 (REQ)
    // 指定した transType(とタグ条件)に一致する保存済みイベントをサーバーが PUSH で返してくる。
    public sendReq(req: FodprReq) {
        if (!this.ws || this.ws.readyState !== WebSocket.OPEN) {
            throw new Error("WebSocketが接続されていません");
        }

        // encodeReq は先頭にメッセージ種別 REQ(0x02) を含むため、そのまま送るだけでよい
        const payload = Protocol.encodeReq(req);
        this.ws.send(Buffer.from(payload));
        this.log(`[送信] REQ パケット送信[SubId: ${req.subId}, TransType: ${Protocol.transTypeName(req.transType)}]`);
    }

    // 接続を閉じる
    public close() {
        if (this.ws) {
            this.ws.close();
        }
    }
}
