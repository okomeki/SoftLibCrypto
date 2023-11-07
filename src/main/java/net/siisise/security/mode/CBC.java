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

import net.siisise.security.block.Block;

/**
 * Cipher Block Chaining.
 * iv は 0 でいいがJavaのは必須?
 */
public class CBC extends LongBlockMode {

    private long[] vectorl;

    public CBC(Block block) {
        super(block);
        vectorl = new long[block.getBlockLength() / 64];
    }

    /**
     * iv をとる
     * @param params key, [iv]
     */
    @Override
    public void init(byte[]... params) {
        byte[] iv;
        
        byte[][] params2 = params;
        byte[] vector = new byte[block.getBlockLength() / 8];
        if ( params.length > 1 ) {
            iv = params[params.length-1];
            params2 = new byte[params.length-1][];
            System.arraycopy(params, 0, params2, 0, params.length - 1);
            System.arraycopy(iv, 0, vector, 0, iv.length);
        }
        block.init(params2);
        vectorl = btol(vector);
    }

    @Override
    public void init(Block block, byte[] key) {
        super.init(block, key);
        vectorl = new long[block.getBlockLength() / 64];
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        int vl = vectorl.length;
        xor(vectorl, src, offset, vl);
        return ltob(vectorl = block.encrypt(vectorl,0));
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        int vl = vectorl.length;
        long[] lsrc = new long[vl];
        itol(src, offset, lsrc, vl);
        xor(vectorl, lsrc, 0, vl);
        return ltoi(vectorl = block.encrypt(vectorl,0));
    }

    @Override
    public long[] encrypt(long[] src, int offset) {
        xor(vectorl, src, offset, vectorl.length);
        long[] ret = block.encrypt(vectorl,0);
        // 複製が必要かもしれない
        System.arraycopy(ret, 0, vectorl, 0, ret.length);
        return ret;
    }

    /**
     * byte to long
     * @param src 平文 plane text
     * @param offset
     * @param length
     * @return 暗号列
     */

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int vl = vectorl.length;
        byte[] ret = new byte[length];
        int o4 = 0;
        
        while (o4 < length) {
            xor(vectorl, src, offset + o4, vl);

            vectorl = block.encrypt(vectorl, 0);
            
            ltob(vectorl,ret,o4);
            o4 += vl*8;
        }
        return ret;
    }

    @Override
    public long[] encrypt(long[] src, int offset, int length) {
        int vl = vectorl.length;
        long[] ret = new long[length];
        int roffset = 0;

        while (length > 0) {
//          XOR
            for (int i = 0; i < vl; i++) {
                vectorl[i] ^= src[offset++];
            }
            vectorl = block.encrypt(vectorl, 0);
            // 複製が必要かもしれない
            System.arraycopy(vectorl, 0, ret, roffset, vl);
            length -= vl;
            roffset += vl;
        }
        return ret;
    }

    /**
     * 復号
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        long[] n = btol(src, offset, vectorl.length);
        long[] ret = block.decrypt(n, 0);
        // 複製が必要かもしれない
        xor(ret,vectorl,0,vectorl.length);
        vectorl = n;
        return ltob(ret);
    }

    /**
     * byte to int decrypt
     * ToDo: 並列化が可能
     * @param src 暗号文
     * @param offset 位置
     * @param length 長さ
     * @return 平文
     */
    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        byte[] ret = new byte[length];
//        int bl = ;

//        Blocks.subBlocks(src,128).stream();

        for (int toffset = 0; toffset < length; ) {
            long[] ls = btol(src, offset + toffset, vectorl.length);
            long[] re = block.decrypt(ls, 0);
            
            for (int i = 0; i < vectorl.length; i++, toffset+=8) {
                long x = re[i] ^ vectorl[i];
                
                ret[toffset  ] = (byte)(x >> 56);
                ret[toffset+1] = (byte)(x >> 48);
                ret[toffset+2] = (byte)(x >> 40);
                ret[toffset+3] = (byte)(x >> 32);
                ret[toffset+4] = (byte)(x >> 24);
                ret[toffset+5] = (byte)(x >> 16);
                ret[toffset+6] = (byte)(x >>  8);
                ret[toffset+7] = (byte) x;
            }
            vectorl = ls;
        }
        return ret;
    }

    /**
     * 
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public long[] decrypt(long[] src, int offset, int length) {
        int bl = vectorl.length;

        if ( length < bl) {
            return new long[0];
        }

        int roffset = 0;
        long[] ret = new long[length];
        long[] re;

        re = block.decrypt(src, offset);
        for (int i = 0; i < bl; i++) {
            ret[roffset+i] = re[i] ^ vectorl[i];
        }
        length += offset;
        offset += bl;

        while (length > offset) {
            re = block.decrypt(src, offset);
            for (int i = 0; i < bl; i++) {
                ret[roffset+i] = re[i] ^ src[offset - bl];
            }
            offset += bl;
            roffset += bl;
        }
        System.arraycopy(src, offset - bl, vectorl, 0, bl);
        return ret;
    }

    /**
     * 
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public long[] decrypt(long[] src, int offset) {
        long[] n = new long[vectorl.length];
        System.arraycopy(src, offset, n, 0, vectorl.length);
        long[] ret = block.decrypt(n, 0);
        // 複製が必要かもしれない
//        xor(ret,vectori,0,vectori.length);
        for (int i = 0; i < vectorl.length; i++) {
            ret[i] ^= vectorl[i];
        }
        vectorl = n;
        return ret;
    }
}
