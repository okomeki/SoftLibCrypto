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

public class cSHAKE128 extends cSHAKE implements XOF {

    /**
     * cSHAKE128.
     * @param d 出力長 標準? 256bitぐらい
     * @param N 関数名
     * @param S カスタマイズ名
     */
    public cSHAKE128(int d, String N, String S) {
        super(128,d,N,S);
    }
}
