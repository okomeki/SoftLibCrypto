/*
 * Copyright 2022 okome.
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

import java.security.MessageDigest;
import java.util.Arrays;

/**
 * RFC 8018 5.1. PBKDF1
 * 鍵導出関数. Key Derivation Function KDF.
 * ハッシュ長までの派生鍵を生成できる.
 * @deprecated 互換用 推奨されていない
 */
@Deprecated
public class PBKDF1 implements PBKDF {

    private MessageDigest md;
    private byte[] salt;
    private int c;
    private int dkLen;

    public PBKDF1() {
    }

    public PBKDF1(MessageDigest md) {
        this.md = md;
    }

    public void init(MessageDigest md) {
        this.md = md;
    }

    /**
     * 
     * @param md
     * @param salt salt, an octet string
     * @param c iteration count, positive integer 繰り返し数 4000ぐらい
     */
    public void init(MessageDigest md, byte[] salt, int c) {
        this.md = md;
        this.salt = salt;
        this.c = c;
    }

    /**
     * 
     * @param md
     * @param salt salt, an octet string
     * @param c iteration count, positive integer 繰り返し数 4000ぐらい
     * @param dkLen length in octets of derived key, a positive integer 派生鍵の長さ  (最大値はMDにより異なる)
     */
    public void init(MessageDigest md, byte[] salt, int c, int dkLen) {
        this.md = md;
        this.salt = salt;
        this.c = c;
        this.dkLen = dkLen;
    }
    
    /**
     * ハッシュ長までの派生鍵を生成するよ.
     * @param password ぱすわーど
     * @param salt salt, an octet string
     * @param c iteration count, positive integer 繰り返し数 4000ぐらい
     * @param dkLen length in octets of derived key, a positive integer 派生鍵の長さ  (最大値はMDにより異なる)
     * @return DK derived key 派生鍵
     */
    @Override
    public byte[] pbkdf(byte[] password, byte[] salt, int c, int dkLen) {
        return pbkdf1(md, password, salt, c, dkLen);
    }

    /**
     * ハッシュ長までの派生鍵を生成するよ.
     * @param password ぱすわーど
     * @param dkLen length in octets of derived key, a positive integer 派生鍵の長さ  (最大値はMDにより異なる)
     * @return DK derived key 派生鍵 長さ dkLen
     */
    @Override
    public byte[] kdf(byte[] password, int dkLen) {
        return pbkdf1(md, password, salt, c, dkLen);
    }

    /**
     * ハッシュ長までの派生鍵を生成するよ.
     * @param password ぱすわーど
     * @return DK derived key 派生鍵
    */
    @Override
    public byte[] kdf(byte[] password) {
        return pbkdf1(md, password, salt, c, dkLen);
    }
    
    /**
     * RFC 8018 5.1. PBKDF1
     * 鍵導出関数. Key Derivation Function KDF.
     *
     * PKCS#5 v1.5 互換
     * MD2,MD5 16オクテット
     * SHA-1 20オクテット
     *
     * @param digest MD2 [RFC 1319], MD5 [RFC 1321], SHA-1 [NIST180]
     * @param pass P password, an octet string
     * @param salt S salt, an octet string
     * @param c iteration count, a positive integer ハッシュ繰り返し数
     * @param dkLen 派生鍵の鍵バイト長 (MD2, MD5 最大16, SHA-1 最大20)
     * @return DK 派生鍵 長さ dkLen
     * @deprecated 互換用
     */
    @Deprecated
    public static byte[] pbkdf1(MessageDigest digest, byte[] pass, byte[] salt, int c, int dkLen) {
        // Step 1
        if (digest.getDigestLength() < dkLen) {
            throw new SecurityException("derived key too long 派生キーが長すぎます");
        }
        // T_1
        digest.update(pass);
        byte[] t1 = digest.digest(salt);
        // T_c
        for (int i = 2; i <= c; i++) {
            t1 = digest.digest(t1);
        }
        // DK
        return Arrays.copyOf(t1, dkLen);
    }
}
