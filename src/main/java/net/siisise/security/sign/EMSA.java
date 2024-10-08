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

import java.nio.ByteBuffer;

/**
 * Section 9. の EMSA-XXXX-ENCODE -VERIFY のまとめ
 */
public interface EMSA {
    
    /**
     * Mを分割できるような拡張 (MessageDigest, MACとおなじ)
     * @param M メッセージの一部
     */
    void update(byte[] M);
    void update(byte[] M, int offset, int length);
    void update(ByteBuffer buffer);

    /*
     * 受け取ってハッシュにかけたMのサイズ
     * @return Mのサイズ
     */
    long size();
    
    /**
     * 署名前のコード生成.
     * 事前にupdateでM メッセージが必要
     * @param emLen ビット数またはバイト数 まだ揃えていない
     * @return EM 署名
     */
    byte[] encode(int emLen);
    
    /**
     * 署名前のコード生成.
     * @param M メッセージ
     * @param emLen emBits maximal bit length of the integer
     * @return EM 署名
     */
    default byte[] encode(byte[] M, int emLen) {
        update(M);
        return encode(emLen);
    }

    /**
     * 署名確認.
     * 事前にupdateでM メッセージが必要
     * @param EM 署名
     * @param emLen
     * @return 
     */
    boolean verify(byte[] EM, int emLen);

    /**
     * 署名確認.
     * @param M メッセージ
     * @param EM 署名
     * @param emLen
     * @return 
     */
    default boolean verify(byte[] M, byte[] EM, int emLen) {
        update(M);
        return verify(EM, emLen);
    }
}
