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

import net.siisise.io.Output;

/**
 * 署名用.
 * 型式別に分ける?
 */
public interface Signer extends Output {

    /**
     * メッセージ本文の追加. 長さ指定を省略したもの.
     *
     * @param src 分割可能本文
     */
    default void update(byte[] src) {
        update(src, 0, src.length);
    }

    /**
     * 本文の追加。
     * 分割追加が可能.
     * 
     * @param src 本文
     * @param offset src内の開始位置
     * @param length 本文長さ
     */
    void update(byte[] src, int offset, int length);

    /**
     * sign 署名.
     *
     * @return signature
     */
    byte[] sign();

    @Override
    default public Output put(byte[] data, int offset, int length) {
        update(data, offset, length);
        return this;
    }
}
