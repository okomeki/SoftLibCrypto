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
 * @deprecated 互換用 推奨されていない
 */
public class PBKDF1 implements PBKDF {

    private MessageDigest md;
    private byte[] salt;
    private int c;

    public PBKDF1() {
    }

    public PBKDF1(MessageDigest md) {
        this.md = md;
    }

    public void init(MessageDigest md) {
        this.md = md;
    }

    public void init(MessageDigest md, byte[] salt, int c) {
        this.md = md;
        this.salt = salt;
        this.c = c;
    }

    /**
     *
     * @param password
     * @param salt
     * @param c
     * @param dkLen ハッシュ鍵長 (最大値はMDにより異なる)
     * @return
     */
    @Override
    public byte[] pbkdf(byte[] password, byte[] salt, int c, int dkLen) {
        return pbkdf1(md, password, salt, c, dkLen);
    }
    
    @Override
    public byte[] pbkdf(byte[] password, int dkLen) {
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
     * @param salt S salt, an octet string 8ばいと文字列
     * @param c ハッシュ繰り返し数
     * @param dkLen ハッシュの鍵バイト長 (MD2, MD5 最大16, SHA-1 最大20)
     * @return DK 戻り値 長さ dkLen
     * @deprecated 互換用
     */
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
