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
package net.siisise.security.mac;

/**
 * XOF 可変長っぽく.
 */
public class KMACXOF128 extends KMAC128 {

    /**
     * 初期値.
     * @param key 鍵
     * @param length XOF出力サイズ 0 &lt;= L &lt; 2^2040 bit
     * @param S オプションで設定可能な空文字列を含む可変長文字列. optional customization bit string of any length, including zero. len(S) &lt; 2^2040
     */
    @Override
    public void init(byte[] key, int length, String S) {
        super.init(key, length, S);
        L = 0;
    }

}
