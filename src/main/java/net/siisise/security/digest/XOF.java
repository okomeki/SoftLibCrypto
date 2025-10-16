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

import net.siisise.io.Output;

/**
 * extendable-output function.
 * SHA-3 SHAKE系 XOF型.
 * MessageDigestに追加する
 * interface にするか class か未定.
 */
public interface XOF {

    /**
     * ハッシュ出力長.
     *
     * @return バイト単位出力長
     */
    int getDigestLength();

    /**
     * ビット単位の出力長.
     * 
     * @return ビット単位の出力長
     */
    long getBitDigestLength();

    /**
     * XOFの出力サイズをあとから変更する.
     * 後から変更できないものはException出したい.
     *
     * @param length 出力バイト長
     */
    void setDigestLength(int length);

    /**
     * XOFの出力サイズをあとから変更する.
     * 後から変更できないものはException出したい.
     * 
     * @param length 出力ビット長
     */
    void setBitDigestLength(long length);
    
    /**
     * ハッシュ偽装用.
     * @return ブロックのビット長
     */
    int getBitBlockLength();

    void update(byte[] src);
    void update(byte[] src, int offset, int length);

    /**
     * MessageDigest 互換.
     * @return ハッシュ出力
     */
    byte[] digest();
    /**
     * MessageDigest 互換.
     * @param src 入力の最後
     * @return ハッシュ出力
     */
    byte[] digest(byte[] src);
    /**
     * 連続出力が可能な型式.
     * @param out 出力先
     */
    void digest(Output out);

}
