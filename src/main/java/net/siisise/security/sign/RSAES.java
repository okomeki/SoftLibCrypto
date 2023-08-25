/*
 * Copyright 2023 okome.
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
package net.siisise.security.sign;

import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;
import net.siisise.security.padding.EME;

/**
 * RFC 8017 PKCS #1
 * Section 7 Encryption Schemes とりあえずまとめ
 * modulus より短いデータのPadding と署名
 * 
 * IEEE 1363
 */
public class RSAES {
    EME eme;

    public RSAES(EME eme) {
        this.eme = eme;
    }

    /**
     * RSAES-XXXX-ENCRYPT
     * RFC 8017 7.1.1. 7.2.1. Encryption Operation をまとめたもの
     * @param pub PublicKey 受信者のRSA公開鍵 k modulus nの長さ
     * @param m メッセージ mLen 長さ
     * @return C ciphertext 暗号文
     */
    public byte[] encrypt(RSAPublicKey pub, byte[] m) {
        int k = (pub.getModulus().bitLength() + 7) / 8;
        byte[] EM = eme.encoding(k, m);
        return pub.rsaep(EM, k);
    }

    /**
     * RSAES-XXXX-DECRYPT
     * RFC 8017 7.1.2. 7.2.2. Decription Operation をまとめたもの
     * @param prv 秘密鍵
     * @param c ciphertext 暗号文
     * @return メッセージ 
     */
    public byte[] decrypt(RSAMiniPrivateKey prv, byte[] c) {
        int k = (prv.getModulus().bitLength() + 7) / 8;
        try {
            eme.decodeCheck(k, c);
            byte[] EM = prv.rsadp(c, k);
            return eme.decode(EM);
        } catch ( SecurityException e) { // ばれないように一カ所で再度発する.
            throw new SecurityException("decryption error");
        }
    }
}
