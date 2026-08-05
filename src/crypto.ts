/**
 * crypto.ts
 * ---------
 * Fodpr で使う暗号まわりのユーティリティ。
 *
 * Fodpr の署名は secp256k1 (ECDSA) を使う。サーバー側(Nim の crypto.nim)は
 * コンテンツを SHA-256 でハッシュしたダイジェストに対して署名・検証を行うため、
 * この SDK も同じく「コンテンツの SHA-256 ダイジェスト」に対する署名を生成する。
 * (noble/secp256k1 の sign/verify はデフォルトでメッセージを SHA-256 でハッシュする)
 */

import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha2.js';
import * as utils from '@noble/hashes/utils.js'
const { bytesToHex, hexToBytes } = utils;

// noble/secp256k1 が署名・検証時に使うハッシュ関数を SHA-256 に設定する。
// (secp256k1 の ECDSA はメッセージのハッシュに依存するため、必ずサーバーと
//  同じハッシュ関数でなくてはならない)
secp.hashes.sha256 = sha256;
secp.hashes.sha256Async = async (msg) => sha256(msg);

export class CryptoUtils {
    // ランダムな秘密鍵(32 バイト)を HEX 文字列で生成する。
    public static generatePrivateKey(): string {
        const privKey = secp.etc.randomBytes(32);
        return bytesToHex(privKey);
    }

    // 秘密鍵から圧縮公開鍵(33 バイト)を Uint8Array で取得する。
    // 公開鍵の形式は Fodpr のイベントでそのまま使う圧縮形式。
    public static getRawCompressedPublicKey(privKeyInput: string | Uint8Array): Uint8Array {
        const privKeyBytes = typeof privKeyInput === 'string' ? hexToBytes(privKeyInput) : privKeyInput;
        return secp.getPublicKey(privKeyBytes, true);
    }

    // 秘密鍵から圧縮公開鍵を HEX 文字列で取得する。
    public static getPublicKey(privKeyInput: string | Uint8Array): string {
        const pubKeyBytes = this.getRawCompressedPublicKey(privKeyInput);
        return bytesToHex(pubKeyBytes);
    }

    // メッセージバイト列に対する ECDSA 署名を生成する(compact 形式 64 バイトの HEX)。
    // サーバー側の verifyContent と同じく SHA-256 ハッシュ後のダイジェストに対して署名される。
    public static async signMessage(privKeyInput: string | Uint8Array, messageBytes: Uint8Array): Promise<string> {
        const privKeyBytes = typeof privKeyInput === 'string' ? hexToBytes(privKeyInput) : privKeyInput;
        const sig = await secp.signAsync(messageBytes, privKeyBytes);
        return bytesToHex(sig);
    }

    // 公開鍵・メッセージ・署名から署名の正当性を検証する。
    // 不正な署名や形式が壊れた入力は false を返す。
    public static async verifySignature(pubKeyInput: string | Uint8Array, messageBytes: Uint8Array, sigInput: string | Uint8Array): Promise<boolean> {
        try {
            const pubKeyBytes = typeof pubKeyInput === 'string' ? hexToBytes(pubKeyInput) : pubKeyInput;
            const sigBytes = typeof sigInput === 'string' ? hexToBytes(sigInput) : sigInput;
            return await secp.verifyAsync(sigBytes, messageBytes, pubKeyBytes);
        } catch {
            return false;
        }
    }

    // HEX 文字列を Uint8Array に変換する。
    public static hexToBytes(hex: string): Uint8Array {
        return hexToBytes(hex);
    }

    // Uint8Array(またはそのままの HEX 文字列)を HEX 文字列に変換する。
    public static bytesToHex(bytes: Uint8Array | string): string {
        if (typeof bytes === 'string') {
            return bytes;
        }
        return bytesToHex(bytes);
    }
}
