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
 * 検証用.
 * 鍵の設定が別途必要.
 */
public interface Verifyer extends Output {
    /**
     * メッセージ本文の追加.
     * 分割して追加可能.
     * @param src 本文
     */
    default void update(byte[] src) {
        update(src,0,src.length);
    }

    void update(byte[] src, int offset, int length);

    /**
     * verify 検証.
     *
     * @param signature 署名
     * @return 検証結果
     */
    boolean verify(byte[] signature);

    @Override
    default public Output put(byte[] data, int offset, int length) {
        update(data, offset, length);
        return this;
    }
}
