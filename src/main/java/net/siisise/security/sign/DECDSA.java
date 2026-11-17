/*
 * Copyright 2026 okome.
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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import net.siisise.io.PacketA;
import net.siisise.security.key.ECDSAPrivateKey;
import net.siisise.security.key.ECDSAPublicKey;
import net.siisise.security.mac.HMAC;

/**
 * RFC 6979 決定論的
 * 鍵の生成にHMAC_DRBGを使用しているのかもしれない
 */
public class DECDSA extends ECDSA {

    /**
     * 署名用.
     * @param prv 秘密鍵
     * @param h ダイジェスト関数
     */
    public DECDSA(ECDSAPrivateKey prv, MessageDigest h) {
        super(prv, h);
    }

    /**
     * 検証用.
     * 検証では変更点なし.
     * 
     * @param pub 公開鍵
     * @param h ダイジェスト関数
     */
    public DECDSA(ECDSAPublicKey pub, MessageDigest h) {
        super(pub, h);
    }

    BigInteger genK(byte[] h) {
        return genK(h, md, prv.getS(), E.getN());
    }
    
    /**
     * ハッシュ値から乱数の代わりになるものを生成.
     * HMAC_DRBG らしい.
     * 
     * @param h HMAC_DRBGのnonce 3.2. a. h1 = H(m) 本文digest
     * @return k
     */
    static BigInteger genK(byte[] h, MessageDigest md, BigInteger x, BigInteger q) {
        Deterministic de = new Deterministic(q);

        // 3.2. kの生成
        int qlen = de.qlen;
        HMAC hmac = new HMAC(md);
        // hlen 仕様ではbit ここではbyte
        int hlen = md.getDigestLength();
        // 3.2. c. K の変数代用
        byte[] V = new byte[hlen];
        hmac.init(V); // K
        // 3.2. b.
        Arrays.fill(V, (byte) 0x01); // SHA-256の場合
        // 3.2. d.
        // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
        byte[] ox = de.int2octets(x); // 秘密鍵x
        byte[] nonce = de.bits2octets(h); // K = h1 mod q

        hmac.update(V);
        hmac.update(new byte[]{0});
        hmac.update(ox); // 秘密鍵 x [1, q-1]
        hmac.update(nonce);
        byte[] K = hmac.sign();

        // 3.2. e
        hmac.init(K);
        hmac.update(V);
        V = hmac.sign();

        // f.
        // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))

        hmac.update(V);
        hmac.update(new byte[]{1});
        hmac.update(ox); // 秘密鍵 x [1, q-1]
        hmac.update(nonce);
        K = hmac.sign();

        BigInteger k;
        PacketA T = new PacketA();
        // h.
        do {

            // g.
            hmac.init(K);
            hmac.update(V);
            V = hmac.sign();

            // h. 2.
            while (T.size() * 8 < qlen) {
                hmac.update(V);
                V = hmac.sign();
                T.put(V);
            }

            // h. 3.
            k = de.bits2int(T.toByteArray());

            // K = HMAC_K(V || 0x00)
            hmac.init(K);
            hmac.update(V);
            hmac.update(new byte[]{0});
            K = hmac.sign();

        } while ((BigInteger.ZERO.compareTo(k) >= 0)
                || (k.compareTo(q) >= 0));
        return k;
    }

    /**
     * 2.4. 署名の生成 HMAC_DRBG があるといいかも
     *
     * @return
     */
    @Override
    public byte[] sign() {
        // 1. H(m) から qを法とする整数に変換
        byte[] h = md.digest();

        BigInteger q = E.getN(); // order
        BigInteger k = genK(h, md, prv.getS(), q);

        return sign(h, k);
    }

}
