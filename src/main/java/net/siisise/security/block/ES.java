/*
 * Copyright 2024 okome.
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

/**
 * Encryption Schemas.
 * RSAESのさらに汎用.
 * RSAなど長文ではない暗号用.
 * Block暗号 Stream暗号と分けておく?
 * 仮.
 * 暗号文と平文で長さは異なる前提.
 */
public interface ES {

    /**
     * 暗号化.
     *
     * @param m メッセージ
     * @return c 暗号文
     */
    byte[] encrypt(byte[] m);

    /**
     * 復号
     *
     * @param c 暗号文
     * @return メッセージ
     */
    byte[] decrypt(byte[] c);
}
