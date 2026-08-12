/**
 * crypto.ts
 * ---------
 * Fodpr で使う暗号まわりのユーティリティ。
 *
 * Fodpr の署名は secp256k1 (ECDSA) を使う。
 * - 後方互換: コンテンツを SHA-256 でハッシュしたダイジェストに対して署名・検証
 * - TransTypeSigned / TransTypeEncrypted: イベント全体(メタデータ込み)の署名
 * - TransTypeEncrypted: Bech32 (fpub/fsec) による鍵の文字列表現
 * - TransTypeEncrypted: 宛先別暗号化エンベロープ (gift-wrap 相当)
 *
 * 暗号化 (AES-256-GCM) には Node.js の crypto モジュールを使用する。
 * ECDH キー共有には @noble/secp256k1 の getSharedSecret を使用する。
 */

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import * as utils from '@noble/hashes/utils.js';
import * as nodeCrypto from 'crypto';

const { bytesToHex, hexToBytes } = utils;

// secp256k1 が署名・検証時に使うハッシュ関数を SHA-256 に設定する。
secp.hashes.sha256 = sha256;
secp.hashes.sha256Async = async (msg: Uint8Array) => sha256(msg);

// Bech32 で使用する 32 文字の文字集合 (BIP-173 準拠)。
// 視認性が悪い "0", "1", "b", "i", "o" などを意図的に除外している。
const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

// Envelope 暗号化関連の定数
const ENVELOPE_VERSION = 0x01;
const ENVELOPE_NONCE_LEN = 12;
const ENVELOPE_TAG_LEN = 16;
const ENVELOPE_KEY_LEN = 32;
const ENVELOPE_RECIPIENT_BLOCK_LEN = 33 + ENVELOPE_NONCE_LEN + ENVELOPE_KEY_LEN + ENVELOPE_TAG_LEN;
const ENVELOPE_CONTEXT = "FodprEnvelopeV1";

/**
 * AES-256-GCM 暗号化 (Node.js crypto.createCipheriv を使用)。
 */
function gcmEncrypt(key: Uint8Array, nonce: Uint8Array, plain: Uint8Array, aad: Uint8Array = new Uint8Array()): { ciphertext: Uint8Array; tag: Uint8Array } {
    const cipher = nodeCrypto.createCipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce));
    if (aad.length > 0) {
        (cipher as any).setAAD(Buffer.from(aad));
    }
    const ct = Buffer.concat([cipher.update(Buffer.from(plain)), cipher.final()]);
    const tag = (cipher as any).getAuthTag();
    return { ciphertext: new Uint8Array(ct), tag: new Uint8Array(tag) };
}

/**
 * AES-256-GCM 復号 (Node.js crypto.createDecipheriv を使用)。
 */
function gcmDecrypt(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array, tag: Uint8Array, aad: Uint8Array = new Uint8Array()): Uint8Array {
    const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', Buffer.from(key), Buffer.from(nonce));
    if (aad.length > 0) {
        (decipher as any).setAAD(Buffer.from(aad));
    }
    (decipher as any).setAuthTag(Buffer.from(tag));
    try {
        const pt = Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
        return new Uint8Array(pt);
    } catch {
        throw new Error("Envelope decryption failed (authentication tag mismatch)");
    }
}

/**
 * Bech32 のチェックサム計算に使う多項式剰余 (polymod)。
 */
function bech32Polymod(values: number[]): number {
    let chk = 1;
    const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    for (const v of values) {
        const top = chk >>> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (let i = 0; i < 5; i++) {
            if (((top >>> i) & 1) !== 0) {
                chk ^= generator[i];
            }
        }
    }
    return chk;
}

/**
 * HRP (Human Readable Part) を polymod 用の値へ変換する。
 */
function bech32ExpandHrp(hrp: string): number[] {
    const result: number[] = [];
    for (let i = 0; i < hrp.length; i++) {
        result[i] = hrp.charCodeAt(i) >>> 5;
    }
    result[hrp.length] = 0;
    for (let i = 0; i < hrp.length; i++) {
        result[hrp.length + 1 + i] = hrp.charCodeAt(i) & 31;
    }
    return result;
}

/**
 * データのビット幅を変換する (例: 8bit -> 5bit, 5bit -> 8bit)。
 */
function bech32ConvertBits(data: Uint8Array, fromBits: number, toBits: number, pad: boolean): number[] {
    let acc = 0;
    let bits = 0;
    const maxv = (1 << toBits) - 1;
    const result: number[] = [];
    for (const b of data) {
        acc = (acc << fromBits) | b;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            result.push((acc >> bits) & maxv);
        }
    }
    if (pad) {
        if (bits > 0) {
            result.push((acc << (toBits - bits)) & maxv);
        }
    } else {
        if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
            throw new Error("Invalid padding in convertBits");
        }
    }
    return result;
}

/**
 * 8bit バイト列を Bech32 文字列 (hrp + "1" + データ + 6文字チェックサム) に変換する。
 */
function bech32Encode(hrp: string, data: Uint8Array): string {
    const converted = bech32ConvertBits(data, 8, 5, true);
    const combined = bech32ExpandHrp(hrp).concat(converted).concat([0, 0, 0, 0, 0, 0]);
    const pm = bech32Polymod(combined) ^ 1;
    const checksum: number[] = [];
    for (let i = 0; i < 6; i++) {
        checksum[5 - i] = (pm >> (i * 5)) & 31;
    }
    const allData = converted.concat(checksum);
    let result = hrp + "1";
    for (const v of allData) {
        result += CHARSET[v];
    }
    return result;
}

/**
 * Bech32 文字列を検証しつつ、データ部分を 8bit バイト列へ復元する。
 */
function bech32Decode(bechStr: string, expectedHrp: string): Uint8Array {
    if (bechStr.length < 8) {
        throw new Error("Bech32 string too short");
    }
    const pos = bechStr.lastIndexOf("1");
    if (pos === -1 || pos < 1 || pos + 7 > bechStr.length) {
        throw new Error("Invalid Bech32 format");
    }
    const hrp = bechStr.substring(0, pos).toLowerCase();
    if (hrp !== expectedHrp.toLowerCase()) {
        throw new Error(`HRP mismatch: expected ${expectedHrp}, got ${hrp}`);
    }
    const data: number[] = [];
    for (let i = pos + 1; i < bechStr.length; i++) {
        const c = bechStr[i];
        const idx = CHARSET.indexOf(c);
        if (idx === -1) {
            throw new Error("Invalid character in Bech32 string");
        }
        data.push(idx);
    }
    if (data.length < 6) {
        throw new Error("Bech32 data too short");
    }
    const toDecode = data.slice(0, data.length - 6);
    // チェックサム検証
    const hrpExpanded = bech32ExpandHrp(hrp);
    const checksum = data.slice(data.length - 6);
    const checkValues = hrpExpanded.concat(toDecode).concat([0, 0, 0, 0, 0, 0]);
    for (let i = 0; i < 6; i++) {
        checkValues[checkValues.length - 6 + i] = checksum[i];
    }
    if (bech32Polymod(checkValues) !== 1) {
        throw new Error("Invalid Bech32 checksum");
    }
    // 5bit -> 8bit 変換
    return new Uint8Array(bech32ConvertBits(new Uint8Array(toDecode), 5, 8, false));
}

export class CryptoUtils {
    // -----------------------------------------------------------------------
    // 基本的な鍵生成・署名・検証 (後方互換)
    // -----------------------------------------------------------------------

    /**
     * ランダムな秘密鍵 (32 バイト) を HEX 文字列で生成する。
     */
    public static generatePrivateKey(): string {
        const privKey = secp.etc.randomBytes(32);
        return bytesToHex(privKey);
    }

    /**
     * 秘密鍵から圧縮公開鍵 (33 バイト) を Uint8Array で取得する。
     */
    public static getRawCompressedPublicKey(privKeyInput: string | Uint8Array): Uint8Array {
        const privKeyBytes = typeof privKeyInput === 'string' ? hexToBytes(privKeyInput) : privKeyInput;
        return secp.getPublicKey(privKeyBytes, true);
    }

    /**
     * 秘密鍵から圧縮公開鍵を HEX 文字列で取得する。
     */
    public static getPublicKey(privKeyInput: string | Uint8Array): string {
        const pubKeyBytes = CryptoUtils.getRawCompressedPublicKey(privKeyInput);
        return bytesToHex(pubKeyBytes);
    }

    /**
     * メッセージバイト列に対する ECDSA 署名を生成する (compact 形式 64 バイトの HEX)。
     * サーバー側の verifyContent と同じく SHA-256 ハッシュ後のダイジェストに対して署名される。
     */
    public static async signMessage(privKeyInput: string | Uint8Array, messageBytes: Uint8Array): Promise<string> {
        const privKeyBytes = typeof privKeyInput === 'string' ? hexToBytes(privKeyInput) : privKeyInput;
        const sig = await secp.signAsync(messageBytes, privKeyBytes);
        return bytesToHex(sig);
    }

    /**
     * 公開鍵・メッセージ・署名から署名の正当性を検証する。
     */
    public static async verifySignature(pubKeyInput: string | Uint8Array, messageBytes: Uint8Array, sigInput: string | Uint8Array): Promise<boolean> {
        try {
            const pubKeyBytes = typeof pubKeyInput === 'string' ? hexToBytes(pubKeyInput) : pubKeyInput;
            const sigBytes = typeof sigInput === 'string' ? hexToBytes(sigInput) : sigInput;
            return await secp.verifyAsync(sigBytes, messageBytes, pubKeyBytes);
        } catch {
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // Bech32 エンコーディング (fsec / fpub 形式)
    // -----------------------------------------------------------------------

    /**
     * 秘密鍵 (32 バイト) を "fsec1..." 形式の Bech32 文字列へエンコードする。
     */
    public static fsecEncode(privKeyInput: string | Uint8Array): string {
        const privKeyBytes = typeof privKeyInput === 'string' ? hexToBytes(privKeyInput) : privKeyInput;
        if (privKeyBytes.length !== 32) {
            throw new Error(`Invalid private key length: expected 32, got ${privKeyBytes.length}`);
        }
        return bech32Encode("fsec", privKeyBytes);
    }

    /**
     * 公開鍵 (圧縮形式 33 バイト) を "fpub1..." 形式の Bech32 文字列へエンコードする。
     */
    public static fpubEncode(pubKeyInput: string | Uint8Array): string {
        const pubKeyBytes = typeof pubKeyInput === 'string' ? hexToBytes(pubKeyInput) : pubKeyInput;
        if (pubKeyBytes.length !== 33) {
            throw new Error(`Invalid public key length: expected 33, got ${pubKeyBytes.length}`);
        }
        return bech32Encode("fpub", pubKeyBytes);
    }

    /**
     * "fsec1..." 形式の Bech32 文字列を復号して秘密鍵 (Uint8Array 32 バイト) に戻す。
     */
    public static fsecDecode(fsecStr: string): Uint8Array {
        const bytes = bech32Decode(fsecStr, "fsec");
        if (bytes.length !== 32) {
            throw new Error(`Invalid private key bytes length: expected 32, got ${bytes.length}`);
        }
        return bytes;
    }

    /**
     * "fpub1..." 形式の Bech32 文字列を復号して公開鍵 (Uint8Array 33 バイト) に戻す。
     */
    public static fpubDecode(fpubStr: string): Uint8Array {
        const bytes = bech32Decode(fpubStr, "fpub");
        if (bytes.length !== 33) {
            throw new Error(`Invalid public key bytes length: expected 33, got ${bytes.length}`);
        }
        return bytes;
    }

    // -----------------------------------------------------------------------
    // 全体署名 (TransTypeSigned / TransTypeEncrypted)
    // -----------------------------------------------------------------------

    /**
     * イベント全体 (transType / createdAt / pubkey / tags / content) に対する ECDSA 署名を生成する。
     * 署名対象: encodeEventSignedData のバイト列の SHA-256 ダイジェスト。
     * content のみ署名する signContent と違い、メタデータの改ざんも検出できる。
     *
     * @param privKeyInput 秘密鍵 (HEX 文字列または Uint8Array)
     * @param signedDataBytes 署名対象バイト列 (encodeEventSignedData の出力)
     * @returns 署名 (compact 形式 64 バイトの Uint8Array)
     */
    public static async signEvent(privKeyInput: string | Uint8Array, signedDataBytes: Uint8Array): Promise<Uint8Array> {
        const privKeyBytes = typeof privKeyInput === 'string' ? hexToBytes(privKeyInput) : privKeyInput;
        const sig = await secp.signAsync(signedDataBytes, privKeyBytes);
        return sig;
    }

    /**
     * イベント全体署名の検証。
     * @param pubKeyInput 公開鍵 (HEX 文字列または Uint8Array)
     * @param signedDataBytes 署名対象バイト列
     * @param sigInput 署名 (HEX 文字列または Uint8Array)
     * @returns 検証結果
     */
    public static async verifyEvent(pubKeyInput: string | Uint8Array, signedDataBytes: Uint8Array, sigInput: string | Uint8Array): Promise<boolean> {
        return CryptoUtils.verifySignature(pubKeyInput, signedDataBytes, sigInput);
    }

    /**
     * イベントID (eventId) を計算する (Nim の eventId 相当)。
     * eventId = SHA-256(encodeEventSignedData(event))
     */
    public static eventId(signedDataBytes: Uint8Array): Uint8Array {
        return sha256(signedDataBytes);
    }

    /**
     * イベントID の 16 進文字列表現を返す。
     */
    public static eventIdHex(signedDataBytes: Uint8Array): string {
        const id = CryptoUtils.eventId(signedDataBytes);
        return bytesToHex(id);
    }

    // -----------------------------------------------------------------------
    // エンベロープ暗号化 (TransTypeEncrypted)
    // -----------------------------------------------------------------------

    /**
     * ラップ鍵 W の導出。ECDH 共有鍵にドメイン分離と受信者公開鍵を混ぜることで、
     * 同じ共有鍵でも受信者ごとに異なる W になる (鍵の分離)。
     * Nim の wrapKey と一致するバイト列を生成する。
     */
    private static wrapKey(senderPriv: Uint8Array, recipientPub: Uint8Array): Uint8Array {
        // secp.getSharedSecret は圧縮形式 (33 バイト)を返す: 0x02/0x03 + X座標(32)
        // Nim の ecdh は X座標 (32 バイト)のみを返すため、先頭バイトをスキップする
        const shared = secp.getSharedSecret(senderPriv, recipientPub, true);
        const sharedBytes = shared.slice(1, 33); // X座標の 32 バイト

        const ctx = sha256.create();
        ctx.update(sharedBytes);
        ctx.update(new TextEncoder().encode(ENVELOPE_CONTEXT));
        ctx.update(recipientPub);
        return ctx.digest();
    }

    /**
     * 本文を複数の受信者向けに暗号化したエンベロープを生成する。
     * senderPriv は送信者 (イベントの pubkey の秘密鍵) である。
     *
     * エンベロープ形式:
     *   version(1) | recipientCount(2, BE) | (recipient block × count) |
     *   bodyNonce(12) | bodyTag(16) | bodyCiphertext
     *
     * recipient block (固定長 93 バイト):
     *   recipientPubkey(33) | wrapNonce(12) | wrappedKeyCiphertext(32) | wrappedKeyTag(16)
     *
     * @param body 暗号化する本文
     * @param senderPriv 送信者の秘密鍵 (Uint8Array 32 バイト)
     * @param recipients 受信者の公開鍵リスト (Uint8Array 33 バイト圧縮形式)
     * @returns エンベロープバイナリ (Uint8Array)
     */
    public static encryptEnvelope(
        body: string,
        senderPriv: Uint8Array,
        recipients: Uint8Array[]
    ): Uint8Array {
        if (body.length === 0) {
            throw new Error("body must not be empty");
        }
        if (recipients.length === 0) {
            throw new Error("at least one recipient required");
        }
        if (recipients.length > 65535) {
            throw new Error("too many recipients");
        }

        // メッセージ鍵 K (32B ランダム) と本文の暗号化
        const k = secp.etc.randomBytes(ENVELOPE_KEY_LEN);
        const bodyNonce = secp.etc.randomBytes(ENVELOPE_NONCE_LEN);
        const bodyBytes = new TextEncoder().encode(body);
        const { ciphertext: bodyCt, tag: bodyTag } = gcmEncrypt(k, bodyNonce, bodyBytes);

        // ヘッダ (version | recipientCount BE)
        const result: number[] = [ENVELOPE_VERSION];
        const rc = recipients.length;
        result.push((rc >> 8) & 0xff);
        result.push(rc & 0xff);

        // 受信者ごとの鍵ブロック
        for (const r of recipients) {
            if (r.length !== 33) {
                throw new Error("Invalid recipient pubkey length: expected 33");
            }
            // recipientPubkey(33)
            for (let i = 0; i < 33; i++) result.push(r[i]);

            // ラップ鍵 W の導出
            const w = CryptoUtils.wrapKey(senderPriv, r);

            // wrapNonce(12) | wrappedKeyCiphertext(32) | wrappedKeyTag(16)
            const wrapNonce = secp.etc.randomBytes(ENVELOPE_NONCE_LEN);
            const { ciphertext: wct, tag: wtag } = gcmEncrypt(w, wrapNonce, k);
            for (let i = 0; i < wrapNonce.length; i++) result.push(wrapNonce[i]);
            for (let i = 0; i < wct.length; i++) result.push(wct[i]);
            for (let i = 0; i < wtag.length; i++) result.push(wtag[i]);
        }

        // 本文: bodyNonce(12) | bodyTag(16) | bodyCiphertext
        for (let i = 0; i < bodyNonce.length; i++) result.push(bodyNonce[i]);
        for (let i = 0; i < bodyTag.length; i++) result.push(bodyTag[i]);
        for (let i = 0; i < bodyCt.length; i++) result.push(bodyCt[i]);

        return new Uint8Array(result);
    }

    /**
     * エンベロープを復号する。受信者が宛先に含まれていれば本文を返す。
     * senderPub はイベントの pubkey (送信者) で、ECDH の相手鍵として使う。
     *
     * @param envelope エンベロープバイナリ
     * @param recipientPriv 受信者の秘密鍵 (Uint8Array 32 バイト)
     * @param senderPub 送信者の公開鍵 (Uint8Array 33 バイト圧縮形式)
     * @returns 復号された本文 (文字列)
     */
    public static decryptEnvelope(
        envelope: Uint8Array,
        recipientPriv: Uint8Array,
        senderPub: Uint8Array
    ): string {
        if (!CryptoUtils.isValidEnvelope(envelope)) {
            throw new Error("invalid envelope");
        }

        if (envelope[0] !== ENVELOPE_VERSION) {
            throw new Error("invalid envelope version");
        }

        const rc = (envelope[1] << 8) | envelope[2];
        const myRawBytes = CryptoUtils.getRawCompressedPublicKey(recipientPriv);
        const myRawHex = bytesToHex(myRawBytes);

        // 自分の受信者ブロックを探す
        let matchedNonce: Uint8Array | null = null;
        let matchedCt: Uint8Array | null = null;
        let matchedTag: Uint8Array | null = null;

        let offset = 3;
        for (let i = 0; i < rc; i++) {
            const pubStart = offset;
            const pubBytes = envelope.subarray(pubStart, pubStart + 33);
            const pubHex = bytesToHex(pubBytes);
            offset += 33; // recipientPubkey(33)

            const wrapNonce = envelope.subarray(offset, offset + ENVELOPE_NONCE_LEN);
            offset += ENVELOPE_NONCE_LEN;
            const wct = envelope.subarray(offset, offset + ENVELOPE_KEY_LEN);
            offset += ENVELOPE_KEY_LEN;
            const wtag = envelope.subarray(offset, offset + ENVELOPE_TAG_LEN);
            offset += ENVELOPE_TAG_LEN;

            if (pubHex === myRawHex) {
                matchedNonce = wrapNonce;
                matchedCt = wct;
                matchedTag = wtag;
                break;
            }
        }

        if (matchedNonce === null) {
            throw new Error("recipient is not addressed in this envelope");
        }

        // 自分のブロックのラップ鍵 W を復元して K を取り出す
        const w = CryptoUtils.wrapKey(recipientPriv, senderPub);
        // null チェックを通過したので、! で非 null としてアクセスする
        const k = gcmDecrypt(w, matchedNonce!, matchedCt!, matchedTag!);

        // 本文を復号 (現在位置は全受信者ブロックの直後)
        const bodyNonce = envelope.subarray(offset, offset + ENVELOPE_NONCE_LEN);
        offset += ENVELOPE_NONCE_LEN;
        const bodyTag = envelope.subarray(offset, offset + ENVELOPE_TAG_LEN);
        offset += ENVELOPE_TAG_LEN;
        const bodyCt = envelope.subarray(offset);

        const bodyBytes = gcmDecrypt(k, bodyNonce, bodyCt, bodyTag);
        return new TextDecoder().decode(bodyBytes);
    }

    /**
     * エンベロープの構造を検証する (リレー用)。内容は解釈しない。
     */
    public static isValidEnvelope(envelope: Uint8Array): boolean {
        if (envelope.length < 3 + ENVELOPE_RECIPIENT_BLOCK_LEN + ENVELOPE_NONCE_LEN + ENVELOPE_TAG_LEN) {
            return false;
        }
        if (envelope[0] !== ENVELOPE_VERSION) {
            return false;
        }
        const rc = (envelope[1] << 8) | envelope[2];
        const expected = 3 + rc * ENVELOPE_RECIPIENT_BLOCK_LEN + ENVELOPE_NONCE_LEN + ENVELOPE_TAG_LEN;
        return envelope.length >= expected;
    }

    /**
     * エンベロープに含まれる受信者の公開鍵一覧を返す (リレー用)。
     */
    public static envelopeRecipients(envelope: Uint8Array): Uint8Array[] {
        if (!CryptoUtils.isValidEnvelope(envelope)) {
            throw new Error("invalid envelope");
        }
        const rc = (envelope[1] << 8) | envelope[2];
        const result: Uint8Array[] = [];
        let offset = 3;
        for (let i = 0; i < rc; i++) {
            const pubBytes = envelope.subarray(offset, offset + 33);
            result.push(new Uint8Array(pubBytes));
            offset += ENVELOPE_RECIPIENT_BLOCK_LEN;
        }
        return result;
    }

    // -----------------------------------------------------------------------
    // ユーティリティ
    // -----------------------------------------------------------------------

    /**
     * HEX 文字列を Uint8Array に変換する。
     */
    public static hexToBytes(hex: string): Uint8Array {
        return hexToBytes(hex);
    }

    /**
     * Uint8Array(または HEX 文字列)を HEX 文字列に変換する。
     */
    public static bytesToHex(bytes: Uint8Array | string): string {
        if (typeof bytes === 'string') {
            return bytes;
        }
        return bytesToHex(bytes);
    }

    /**
     * Bech32 エンコード (公開 API)。
     */
    public static bech32Encode(hrp: string, data: Uint8Array): string {
        return bech32Encode(hrp, data);
    }

    /**
     * Bech32 デコード (公開 API)。
     */
    public static bech32Decode(bechStr: string, expectedHrp: string): Uint8Array {
        return bech32Decode(bechStr, expectedHrp);
    }

    /**
     * BASE64 エンコード (シードレスポンスの署名用)。
     */
    public static base64Encode(bytes: Uint8Array): string {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        let result = '';
        for (let i = 0; i < bytes.length; i += 3) {
            const b1 = bytes[i];
            const b2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
            const b3 = i + 2 < bytes.length ? bytes[i + 2] : 0;
            result += chars[b1 >> 2];
            result += chars[((b1 & 0x03) << 4) | (b2 >> 4)];
            result += i + 1 < bytes.length ? chars[((b2 & 0x0f) << 2) | (b3 >> 6)] : '=';
            result += i + 2 < bytes.length ? chars[b3 & 0x3f] : '=';
        }
        return result;
    }

    /**
     * BASE64 デコード (シードレスポンスの署名用)。
     */
    public static base64Decode(str: string): Uint8Array {
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        const lookup = new Uint8Array(256);
        for (let i = 0; i < chars.length; i++) {
            lookup[chars.charCodeAt(i)] = i;
        }
        const result = new Uint8Array(Math.ceil((str.length * 3) / 4));
        let resultPos = 0;
        let bytes: number[] = [];
        for (let i = 0; i < str.length; i++) {
            if (str[i] === '=') break;
            bytes.push(lookup[str.charCodeAt(i)]);
        }
        for (let i = 0; i < bytes.length; i += 4) {
            const b1 = bytes[i];
            const b2 = i + 1 < bytes.length ? bytes[i + 1] : 0;
            const b3 = i + 2 < bytes.length ? bytes[i + 2] : 0;
            const b4 = i + 3 < bytes.length ? bytes[i + 3] : 0;
            result[resultPos++] = (b1 << 2) | (b2 >> 4);
            if (i + 2 <= bytes.length) result[resultPos++] = ((b2 & 0x0f) << 4) | (b3 >> 2);
            if (i + 3 <= bytes.length) result[resultPos++] = ((b3 & 0x03) << 6) | b4;
        }
        return result.subarray(0, resultPos);
    }
}
