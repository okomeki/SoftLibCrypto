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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import net.siisise.io.Output;

/**
 * デジタル署名 署名・検証 をまとめる
 * MAC,RSASSA
 * 鍵生成も必要?
 */
public interface SignVerify extends Signer, Verifyer {

    default byte[] keyGen() {
        byte[] key = new byte[getKeyLength()];
        try {
            SecureRandom.getInstanceStrong().nextBytes(key);
            return key;
        } catch (NoSuchAlgorithmException ex) {
            throw new SecurityException(ex);
        }
    }

    /**
     * 鍵生成用の長さの目安
     *
     * @return 一般的な鍵長でいいかな
     */
    int getKeyLength();

    /**
     * メッセージ本文の追加.
     *
     * @param src 本文
     */
    @Override
    default void update(byte[] src) {
        update(src, 0, src.length);
    }

    /**
     * verify 検証.
     *
     * @param signature 署名
     * @return 検証結果
     */
    @Override
    default boolean verify(byte[] signature) {
        return Arrays.equals(sign(), signature);
    }

    /**
     * 追加.
     * @param data 本文
     * @param offset 本文位置
     * @param length 本文長さ
     * @return これ
     */
    @Override
    default public Output put(byte[] data, int offset, int length) {
        update(data, offset, length);
        return this;
    }
}
