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
 * NIST SP 800-185 cSHAKE.
 * ビット列用だがバイト列で使う.
 *
 */
public class cSHAKE extends RawcSHAKE implements XOF {

    /**
     * cSHAKE.
     * N, Sが空の場合はSHAKEと同じ
     *
     * @param c セキュリティ強度 128 または 256
     * @param d 出力長 bit
     * @param N 関数名のビット文字列
     * @param S 任意の文字列
     */
    public cSHAKE(int c, long d, String N, String S) {
        super("cSHAKE" + c, c, d, N, S);
    }
}
