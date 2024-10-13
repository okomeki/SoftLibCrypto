/*
 * Copyright 2022 Siisise Net.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.siisise.ietf.pkcs5;

import java.util.Arrays;
import net.siisise.block.ReadableBlock;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.digest.SHA1;
import net.siisise.security.mac.HMAC;
import net.siisise.security.mac.MAC;

/**
 * PKCS #5 PBKDF2 パスワードによる鍵導出関数.
 * 疑似乱数関数 PRF が必要。PBKDF2ではHMACだが、MAC系全般が指定可能。
 * デフォルトPRFはHMAC-SHA1だがSHA-1が廃止されているので注意。
 * RFC 2898
 * RFC 8018 PKCS #5 v2.1
 */
public class PBKDF2 implements PBKDF {

    public static final OBJECTIDENTIFIER PKCS5 = PKCS1.PKCS.sub(5); // pkcs-5
    public static final OBJECTIDENTIFIER OID = PKCS5.sub(12); // id-PBKDF2

    byte[] salt;
    /**
     * iterationCount
     */
    int c;
    int dkLen;
    private MAC prf;

    /**
     * デフォルトPRFはHMAC-SHA-1
     *
     * @deprecated SHA-1 は廃止
     */
    @Deprecated
    public PBKDF2() {
        prf = new HMAC(new SHA1()); // 非推奨
    }

    /**
     * 疑似乱数関数を指定して初期化.
     * HMAC-SHA-1 など HMAC-いろいろ、KMACも利用可能.
     * RFC 8018 B.1. では
     * SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 などを想定
     *
     * @param prf 疑似乱数関数PRF HMAC-SHA-xx
     */
    public PBKDF2(MAC prf) {
        this.prf = prf;
    }

    /**
     * 疑似乱数関数PRFの設定.
     *
     * @param prf 疑似乱数関数PRF HMACなど
     */
    public void init(MAC prf) {
        this.prf = prf;
    }

    /**
     * 初期値設定.
     * いくつかのパラメータ設定.
     *
     * @param prf 疑似乱数関数PRF HMACなど
     * @param salt PKCS #5 64bit以上、 アメリカ国立標準技術研究所 128bit 推奨
     * @param c iterationCount 繰り返し数 4000以上くらい
     */
    public void init(MAC prf, byte[] salt, int c) {
        this.prf = prf;
        this.salt = salt;
        this.c = c;
    }

    /**
     * 初期値設定.
     * いくつかのパラメータ設定.
     *
     * @param prf 疑似乱数関数PRF HMACなど
     * @param salt 64bit以上 128bit 推奨
     * @param c iterationCount 繰り返し数 4000以上くらい OpenSSL 2000くらい
     * @param dkLen 派生鍵出力長
     */
    public void init(MAC prf, byte[] salt, int c, int dkLen) {
        this.prf = prf;
        this.salt = salt;
        this.c = c;
        this.dkLen = dkLen;
    }

    /**
     * 初期値設定.
     * いくつかのパラメータ設定.
     *
     * @param salt 64bit以上 128bit 推奨
     * @param c iterationCount 繰り返し数 4000以上くらい OpenSSL 2000くらい
     */
    @Override
    public void init(byte[] salt, int c) {
        this.salt = salt;
        this.c = c;
    }

    /**
     * 初期値設定.
     * 
     * @param salt 64bit以上 128bit 推奨
     * @param c iterationCount 繰り返し数 4000以上くらい OpenSSL 2000くらい
     * @param dkLen 派生鍵出力長
     */
    public void init(byte[] salt, int c, int dkLen) {
        this.salt = salt;
        this.c = c;
        this.dkLen = dkLen;
    }

    /**
     * 派生鍵を生成するよ.
     *
     * @param password HMAC パスワード
     * @param salt ソルト
     * @param c 繰り返す数 1000以上ぐらい
     * @param dkLen 派生鍵出力長
     * @return DK 派生鍵
     */
    @Override
    public byte[] pbkdf(byte[] password, byte[] salt, int c, int dkLen) {
        return pbkdf2(prf, password, salt, c, dkLen);
    }

    /**
     * 派生鍵を生成するよ.
     * 他のパラメータは事前に設定すること.
     *
     * @param password HMAC パスワード
     * @param dkLen 派生鍵出力長
     * @return DK 派生鍵
     */
    @Override
    public byte[] kdf(byte[] password, int dkLen) {
        return pbkdf2(prf, password, salt, c, dkLen);
    }

    /**
     * 派生鍵を生成するよ.
     * 他のパラメータは事前に設定すること.
     *
     * @param password HMAC パスワード
     * @return DK 派生鍵
     */
    @Override
    public byte[] kdf(byte[] password) {
        return pbkdf2(prf, password, salt, c, dkLen);
    }

    /**
     * 複数パラメータを生成する.
     * 一括生成した派生鍵を複数に分割する
     *
     * @param password パスワード
     * @param dkLens 派生鍵出力長 複数指定可能
     * @return 派生鍵
     */
    public byte[][] pbkdf(byte[] password, int... dkLens) {
        int sum = 0;
        for (int i = 0; i < dkLens.length; i++) {
            sum += dkLens[i];
        }

        byte[] dkbase = kdf(password, sum);
        ReadableBlock dk = ReadableBlock.wrap(dkbase);
        byte[][] dks = new byte[dkLens.length][];
        for (int i = 0; i < dkLens.length; i++) {
            dks[i] = new byte[dkLens[i]];
            dk.read(dks[i]);
        }
        return dks;
    }

    /**
     * PBKDF2 本体.
     * HMAC以外も使えるようにしてある
     *
     * @param prf 擬似乱数生成器 MACアルゴリズム
     * @param password HMAC用パスワード
     * @param salt ソルト
     * @param c 繰り返す数
     * @param dkLen 派生鍵長さ (バイト)
     * @return　派生鍵
     */
    public static byte[] pbkdf2(MAC prf, byte[] password, byte[] salt, int c, int dkLen) {
        int hLen = prf.getMacLength();
        // 1.
        if (dkLen > 0xffffffffl * hLen) { // Javaの配列長の範囲外
            throw new IllegalStateException("derived key too long");
        }
        prf.init(password);
        int l = (int) (((long) dkLen + hLen - 1) / hLen); // dkLenに必要なブロック数
        byte[] dk = new byte[l * hLen];
        for (int i = 0; i < l; i++) {
            System.arraycopy(f(prf, salt, c, i + 1), 0, dk, i * hLen, hLen);
        }
        if (dkLen % hLen != 0) {
            return Arrays.copyOf(dk, dkLen);
        }
        return dk;
    }

    /**
     * 内部関数f.
     * 
     * パスワードはHMACで保持できるので省略した
     *
     * @param prf HMAC アルゴリズム パスワード設定済み
     * @param salt ソルト
     * @param c iterationCount ストレッチ回数
     * @param i カウント 長さ由来
     * @return 1回分
     */
    private static byte[] f(MAC prf, byte[] salt, int c, int i) {
        prf.update(salt);
        byte[] u = new byte[4];
        u[0] = (byte) (i >>> 24);
        u[1] = (byte) ((i >> 16) & 0xff);
        u[2] = (byte) ((i >> 8) & 0xff);
        u[3] = (byte) (i & 0xff);
        u = prf.doFinal(u);
        byte[] f = u;
        int len = u.length;
        for (int j = 1; j < c; j++) {
            u = prf.doFinal(u);
            for (int k = 0; k < len; k++) {
                f[k] ^= u[k];
            }
        }
        return f;
    }
}
