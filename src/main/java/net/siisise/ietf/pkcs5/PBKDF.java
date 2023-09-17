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

import net.siisise.security.key.KDF;

/**
 * PKCS #5
 * RFC 8018 5. Key derivation Functions
 * 鍵導出関数?
 */
public interface PBKDF extends KDF {
    
    /**
     * 派生鍵を生成するよ.
     * @param password ぱすわーど
     * @param salt salt, an octet string
     * @param c iteration count, positive integer 繰り返し数 4000ぐらい
     * @param dkLen ハッシュ鍵長 (最大値はKDFにより異なる)
     * @return DK derived key 派生鍵
     */
    byte[] pbkdf(byte[] password, byte[] salt, int c, int dkLen);
    /**
     * 派生鍵を生成するよ.
     * 他のパラメータは事前設定されていること.
     * @param password ぱすわーど
     * @param dkLen ハッシュ鍵長 (最大値はKDFにより異なる)
     * @return DK derived key 派生鍵
     */
    byte[] kdf(byte[] password, int dkLen);
    /**
     * 派生鍵を生成するよ.
     * 他のパラメータは事前設定されていること.
     * @param password ぱすわーど
     * @return DK derived key 派生鍵
     */
    @Override
    byte[] kdf(byte[] password);
}
