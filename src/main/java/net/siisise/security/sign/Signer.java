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

/**
 * 署名用.
 */
public interface Signer {
    /**
     * メッセージ本文の追加.
     * @param src 
     */
    default void update(byte[] src) {
        update(src,0,src.length);
    }

    void update(byte[] src, int offset, int length);

    /**
     * sign 署名.
     *
     * @return signature
     */
    byte[] sign();
}
