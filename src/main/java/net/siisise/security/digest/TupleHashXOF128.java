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
package net.siisise.security.digest;

/**
 * XOFな設定のTupleHash128.
 * 長さタグは0になるため出力サイズに関わらず内容は変化しない.
 */
public class TupleHashXOF128 extends TupleHash128 implements XOF {

    /**
     * 出力サイズとオプションの文字列指定.
     *
     * @param L 実出力長 bit
     * @param S オプションで設定可能な空文字列を含む可変長文字列. optional customization bit string of
     * any length, including zero.
     */
    public TupleHashXOF128(int L, String S) {
        super(L, 0, S);
    }

    /**
     * 出力サイズ256bitでオプションの文字列指定.
     *
     * @param S オプションで設定可能な空文字列を含む可変長文字列. optional customization bit string of
     * any length, including zero.
     */
    public TupleHashXOF128(String S) {
        super(256, 0, S);
    }
}
