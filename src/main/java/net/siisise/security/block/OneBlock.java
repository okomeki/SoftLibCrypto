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
package net.siisise.security.block;

import net.siisise.lang.Bin;

/**
 * バイト列で処理する
 */
public abstract class OneBlock extends BaseBlock {

    @Override
    public int[] encrypt(int[] src, int offset) {
        int bl = getBlockLength() / 32;
        return Bin.btoi(encrypt(Bin.itob(src, offset, bl),0));
    }

    @Override
    public long[] encrypt(long[] src, int offset) {
        int bl = getBlockLength() / 64;
        return Bin.btol(encrypt(Bin.ltob(src, offset, bl),0));
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        int bl = getBlockLength() / 32;
        return Bin.btoi(decrypt(Bin.itob(src, offset, bl),0));
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        int bl = getBlockLength() / 64;
        return Bin.btol(decrypt(Bin.ltob(src, offset, bl),0));
    }

    /**
     * 
     * @param src
     * @param offset
     * @param length 固定サイズの倍数であること.
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int blen = getBlockLength() / 8;
        int len = length / blen;
        byte[] dec = new byte[length];
        byte[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = encrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }

    /**
     * 
     * @param src
     * @param offset
     * @param length 固定サイズの倍数であること.
     * @return 
     */
    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        int blen = getBlockLength() / 32;
        int len = length / blen;
        int[] dec = new int[length];
        int[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = encrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }

    @Override
    public long[] encrypt(long[] src, int offset, int length) {
        int blen = getBlockLength() / 64;
        int len = length / blen;
        long[] dec = new long[length];
        long[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = encrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }

    /**
     *
     * @param src
     * @param offset
     * @param dec
     * @param doffset
     * @param length
     */
    @Override
    public void encrypt(byte[] src, int offset, byte[] dec, int doffset, int length) {
        int blen = getBlockLength() / 8;
        int len = length / blen;
        byte[] bdec;
        for ( int i = 0; i < len; i++ ) {
            bdec = encrypt(src, offset);
            System.arraycopy(bdec, 0, dec, doffset, blen);
            offset += blen;
            doffset += blen;
        }
    }

    /**
     * 復号処理.
     *
     * @param src
     * @param offset
     * @param dst
     * @param doffset
     * @param length
     */
    @Override
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        int blen = getBlockLength() / 8;
        int len = length / blen;
        byte[] bdec;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dst, doffset, blen);
            offset += blen;
            doffset += blen;
        }
    }
}
