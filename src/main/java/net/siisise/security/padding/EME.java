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

/**
 * PKCS #1 Section 7くらい
 */
public interface EME {

    int maxLength(int k);
    /**
     * RSA暗号の前処理 padding等.
     * @param k 出力長
     * @param m データ
     * @return 暗号前Padding文 EM
     */
    byte[] encoding(int k, byte[] m);
    void decodeCheck(int k, byte[] c);
    /**
     * EM からPadding等を除いてMにする
     * @param em Padding文
     * @return M メッセージ
     */
    byte[] decode(byte[] em);
    
}
