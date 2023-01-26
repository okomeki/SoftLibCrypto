/*
 * Copyright 2023 Siisise Net.
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
package net.siisise.security.mode;

import net.siisise.security.block.Block;
import net.siisise.security.stream.Stream;

/**
 * ブロック暗号をストリーム暗号として利用できるモードに.
 *
 */
public abstract class StreamMode extends BlockMode implements Stream {

    protected byte[] vector;
    protected int[] vectori;
    protected int offset;

    StreamMode(Block block) {
        super(block);
    }

//    @Override
//    public int getBlockLength() {
//        return vector.length * 8;
//    }
    /**
     * ストリーム用暗号化.
     *
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public abstract byte[] encrypt(byte[] src, int offset, int length);

    /**
     * ストリーム用復号
     *
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public abstract byte[] decrypt(byte[] src, int offset, int length);

    /**
     * ブロック暗号として利用.
     *
     * @param src
     * @param offset
     * @return
     */
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        return encrypt(src, offset, getBlockLength() / 8);
    }

    /**
     * ブロック暗号として利用.
     *
     * @param src
     * @param offset
     * @return
     */
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return decrypt(src, offset, getBlockLength() / 8);
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        return btoi(encrypt(itob(src, offset, getBlockLength() / 32), 0, getBlockLength() / 8));
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        return btoi(decrypt(itob(src, offset, getBlockLength() / 32), 0, getBlockLength() / 8));
    }
}
