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
package net.siisise.security.padding;

import net.siisise.lang.Bin;

/**
 * RFC 8017 PKCS #1 B.2. Mask Generation Functions マスク生成関数
 * MGF1 の仮
 */
public interface MGF {
    /**
     * マスクの乱数を拡張するっぽい機能.
     * @param seed 種
     * @param maskLen 必要な長さ octet
     * @return マスク
     */
    byte[] generate(byte[] seed, long maskLen);
    default void xorl(byte[] src, byte[] seed) {
        Bin.xorl(src, generate(seed, src.length));
    }
}
