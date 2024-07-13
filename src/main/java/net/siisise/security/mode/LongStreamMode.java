/*
 * Copyright 2024 okome.
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

import net.siisise.lang.Bin;
import net.siisise.security.block.Block;

/**
 *
 */
public abstract class LongStreamMode extends LongBlockMode {

//    protected byte[] vector;
    protected long[] vectorl;

    public LongStreamMode(Block block) {
        super(block);
    }
    
    @Override
    public byte[] encrypt(byte[] src) {
        return encrypt(src, 0, src.length);
    }

    @Override
    public byte[] decrypt(byte[] src) {
        return decrypt(src, 0, src.length);
    }

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
    public long[] encrypt(long[] src, int offset) {
        return Bin.btol(encrypt(Bin.ltob(src, offset, getBlockLength() / 64), 0, getBlockLength() / 8));
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        return Bin.btol(decrypt(Bin.ltob(src, offset, getBlockLength() / 64), 0, getBlockLength() / 8));
    }

}
