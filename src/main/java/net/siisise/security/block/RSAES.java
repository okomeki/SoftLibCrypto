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
package net.siisise.security.block;

import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPrivateCrtKey;
import net.siisise.security.key.RSAPublicKey;
import net.siisise.security.padding.EME;

/**
 * RFC 8017 PKCS #1
 * Section 7 暗号化スキーム Encryption Schemes とりあえずまとめ.
 * modulus より短いデータのPadding と署名
 *
 * RSAESの枠組み と EME に分けて実装してあるだけ.
 *
 * IEEE 1363
 */
public class RSAES implements ES {

    final EME eme;

    private RSAPublicKey pub;
    private RSAMiniPrivateKey prv;
    private int k;

    public RSAES(EME eme) {
        this.eme = eme;
    }

    /**
     * 暗号化用鍵.
     *
     * @param pubKey 公開鍵
     */
    public void init(RSAPublicKey pubKey) {
        pub = pubKey;
        k = (pub.getModulus().bitLength() + 7) / 8;
    }

    /**
     * 暗号、復号用鍵. フル鍵の場合は暗号化も可能
     *
     * @param prvKey 秘密鍵
     */
    public void init(RSAMiniPrivateKey prvKey) {
        prv = prvKey;
        k = (prvKey.getModulus().bitLength() + 7) / 8;
        if (prvKey instanceof RSAPrivateCrtKey) {
            pub = ((RSAPrivateCrtKey) prvKey).getPublicKey();
        }
    }

    /**
     * 符号化可能データ長(1ブロックのみ).
     *
     * @return オクテット
     */
    @Override
    public int getBlockLength() {
        return eme.maxLength(k);
    }

    /**
     * RSAES-XXXX-ENCRYPT.
     * RFC 8017 7.1.1. 7.2.1. Encryption Operation をまとめたもの
     *
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
     * ブロック暗号の作法
     *
     * @param m
     * @return
     */
    @Override
    public byte[] encrypt(byte[] m) {
        byte[] EM = eme.encoding(k, m);
        return pub.rsaep(EM, k);
//        return encrypt(pub,m);
    }

    /**
     * RSAES-XXXX-DECRYPT.
     * RFC 8017 7.1.2. 7.2.2. Decription Operation をまとめたもの
     *
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
        } catch (SecurityException e) { // ばれないように一カ所で再度発する.
            throw new SecurityException("decryption error");
        }
    }

    @Override
    public byte[] decrypt(byte[] c) {
        try {
            eme.decodeCheck(k, c);
            byte[] EM = prv.rsadp(c, k);
            return eme.decode(EM);
        } catch (SecurityException e) { // ばれないように一カ所で再度発する.
            throw new SecurityException("decryption error");
        }
//        return decrypt(prv,c);
    }
}
