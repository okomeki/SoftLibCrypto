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
package net.siisise.ietf.pkcs1;

import java.math.BigInteger;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;

/**
 * RSAっぽいものをまとめるだけ.
 */
public class RSA {

    /**
     * 暗号化 (公開鍵)
     * Section 5.1.1. RSAEP
     *
     * @param key (n, e) 公開鍵
     * @param m message メッセージ 0 から n-1の間の整数
     * @return c ciohertext 暗号 0 から n-1 の間の整数
     */
    public static BigInteger rsaep(RSAPublicKey key, BigInteger m) {
        return key.rsaep(m);
    }

    /**
     * 暗号の復号 (数値渡し) (秘密鍵)
     * Section 5.1.2. RSADP
     * @param key 秘密鍵
     * @param c ciphertext 暗号文 0 ～ n - 1 の整数
     * @return m message メッセージ 0 - n-1 の整数
     */
    public static BigInteger rsadp(RSAMiniPrivateKey key, BigInteger c) {
        return key.rsadp(c);
    }

    /**
     * 暗号の復号 (バイト列渡し)
     * @param key 秘密鍵
     * @param v 暗号
     * @return プレーン
     */
    public static BigInteger rsadp(RSAMiniPrivateKey key, byte[] v) {
        return key.rsadp(v);
    }

    /**
     * 秘密鍵で署名
     * Section 5.2.1. RSASP1
     * @param key 秘密鍵
     * @param m 
     * @return 
     */
    public static BigInteger rsasp1(RSAMiniPrivateKey key, BigInteger m) {
       return key.rsasp1(m);
}

    /**
     * 署名検証的なもの
     * @param key 公開鍵
     * @param s
     * @return 
     */
    public static BigInteger rsavp1(RSAPublicKey key, BigInteger s) {
        return key.rsavp1(s);
    }

}
