/*
 * Copyright 2022 Siisise Net.
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
 * Cipher Feedback.
 * ストリームにも転用可能 (CFB8とかいうらしい)
 * 復号処理の並列化が可能
 */
public final class CFB extends LongStreamMode {
    
    private byte[] vector;
    protected int offset;
    
    public CFB(Block block) {
        super(block);
    }

    public CFB(Block block, byte[] key, byte[] iv) {
        super(block);
        init(key, iv);
    }

    /**
     * 最後のパラメータがCFB用.
     * @param params 鍵とInitial Vector
     */
    @Override
    public void init(byte[]... params) {
        super.init(in(1,params));
        byte[] cfbkey = params[params.length - 1];
        vector = new byte[block.getBlockLength() / 8];

        System.arraycopy(cfbkey, 0, vector, 0, vector.length > cfbkey.length ? cfbkey.length : vector.length);
        vectorl = Bin.btol(vector);
        vectorl = block.encrypt(vectorl, 0);
    }

    /**
     * Block Mode encrypt
     * @param src
     * @param offset
     * @return 
     */
/*
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        xor(vector, src, offset, vector.length);
        byte[] ret = vector;
        vector = block.encrypt(ret, 0);
        return ret;
    }
*/
    @Override
    public long[] encrypt(long[] src, int offset) {
        Bin.xorl(vectorl, src, offset, vector.length);
        long[] ret = vectorl;
        vectorl = block.encrypt(ret, 0);
        return ret;
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        long[] ret = vectorl;
        Bin.xorl(ret, src, offset, ret.length);
        vectorl = block.encrypt(src, offset);
        return ret;
    }

    /**
     * Stream Mode encrypt
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public long[] encrypt(long[] src, int offset, int length) {
        int l = vectorl.length - this.offset;
        long[] ret = new long[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                vectorl[this.offset] ^= src[offset++];
                ret[ro++] = vectorl[this.offset++];
                length--;
            }
            if (this.offset >= vectorl.length) {
                this.offset = 0;
                vectorl = block.encrypt(vectorl, 0);
                l = vectorl.length;
            }
        }
        return ret;
    }

    @Override
    public long[] decrypt(long[] src, int offset, int length) {
        int l = vectorl.length - this.offset;
        long[] ret = new long[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                ret[ro++] = vectorl[this.offset + i] ^ src[offset + i];
                vectorl[this.offset++] = src[offset++];
                length--;
            }
            if (this.offset >= vectorl.length) {
                this.offset = 0;
                vectorl = block.encrypt(vectorl, 0);
                l = vectorl.length;
            }
        }
        return ret;
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int l = vector.length - this.offset;
        byte[] ret = new byte[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                vector[this.offset] ^= src[offset++];
                ret[ro++] = vector[this.offset++];
                length--;
            }
            if (this.offset >= vector.length) {
                this.offset = 0;
                vector = block.encrypt(vector, 0);
                l = vector.length;
            }
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int l = vector.length - this.offset;
        byte[] ret = new byte[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                ret[ro++] = (byte)(vector[this.offset + i] ^ src[offset + i]);
                vector[this.offset++] = src[offset++];
                length--;
            }
            if (this.offset >= vector.length) {
                this.offset = 0;
                vector = block.encrypt(vector, 0);
                l = vector.length;
            }
        }
        return ret;
    }

}
