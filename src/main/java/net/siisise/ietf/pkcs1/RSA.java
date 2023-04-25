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
     * Section .PublicKey
     *
     * @param key 公開鍵
     * @param m メッセージ
     * @return 暗号
     */
    public static BigInteger rsaep(RSAPublicKey key, BigInteger m) {
        return key.rsaep(m);
    }

    /**
     * 暗号の復号 (数値渡し)
     * 
     * @param key 秘密鍵
     * @param c 暗号
     * @return プレーン
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

}
