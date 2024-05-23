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
 * KECCAK Message Authentication Code.
 * SHA-3系に用意されているらしい標準MAC
 * NIST SP 800-185
 * KMAC256(K, X, L, S)
 * K is a bit string of any length, including zero.
 * K 鍵
 * X is the main input bit string.
 * X 主データ update や sign で突っ込む
 * L is an integer representing the requested output length in bits.
 * L 出力長bit
 * S is an optional customization bit string of any length, including zero.
 * S カスタム付加ビット
 */
public class KMAC256 extends KMAC implements MAC {

    public KMAC256() {
    }

    /**
     * 512bit出力固定で初期化.
     * @param key 鍵
     */
    @Override
    public void init(byte[] key) {
        init(key, 512, "");
    }

    /**
     * 初期化要素.
     * @param key 鍵 len(key) &lt; 2^2040
     * @param length XOF出力サイズ 0 &lt;= L &lt; 2^2040
     * @param S オプションで設定可能な空文字列を含む可変長文字列. optional customization bit string of any length, including zero. len(S) &lt; 2^2040
     */
    @Override
    public void init(byte[] key, int length, String S) {
        init(256,key,length,S);
    }
}
