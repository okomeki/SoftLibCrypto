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
package net.siisise.security.key;

/**
 * 鍵導出関数.
 * 擬似的な共通鍵を生成する
 * ASN.1 から出力まで繋げる予定
 */
public interface KDF {

    /**
     * 共通鍵のようなものを生成する.
     * 他の要素はASN.1 などから読み込む想定.
     *
     * @param password パスワードのようなもの(可変長)
     * @return DK 共通鍵的なもの(指定サイズ)
     */
    byte[] kdf(byte[] password);

    /**
     * 共通鍵的なものを生成.
     *
     * @param password パスワードのようなもの
     * @param len 出力サイズバスト
     * @return DK 共通鍵的なもの
     */
    byte[] kdf(byte[] password, int len);
}
