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
 * long[]型で処理する
 */
public abstract class LongBlock extends BaseBlock {

    /**
     * 1ブロック暗号化.
     *
     * @param src 平文ブロック
     * @param offset 位置
     * @return 暗号ブロック
     */
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 64;
        long[] block = new long[bl];
        Bin.btol(src, offset, block, bl);
        return Bin.ltob(encrypt(block, 0));
    }

    /**
     * 1ブロック暗号化.
     *
     * @param src 平文ブロック
     * @param offset 位置
     * @return 暗号ブロック
     */
    @Override
    public int[] encrypt(int[] src, int offset) {
        int bl = getBlockLength() / 64;
        long[] block = new long[bl];
        Bin.itol(src, offset, block, bl);
        return Bin.ltoi(encrypt(block, 0));
    }

    /**
     * 1ブロック復号.
     *
     * @param src 暗号ブロック
     * @param offset 位置
     * @return 平文ブロック
     */
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 64;
        long[] block = new long[bl];
        Bin.btol(src, offset, block, bl);
        return Bin.ltob(decrypt(block, 0));
    }

    /**
     * 1ブロック復号.
     *
     * @param src 暗号ブロック
     * @param offset 位置
     * @return 平文ブロック
     */
    @Override
    public int[] decrypt(int[] src, int offset) {
        int bl = getBlockLength() / 64;
        long[] block = new long[bl];
        Bin.itol(src, offset, block, bl);
        return Bin.ltoi(decrypt(block, 0));
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int l = length / 8;
        long[] srcLong = new long[l];

        Bin.btol(src, offset, srcLong, l);
        long[] ret = encrypt(srcLong, 0, l);
        return Bin.ltob(ret);
    }

    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        int l = length / 2;
        long[] srcLong = new long[l];

        Bin.itol(src, offset, srcLong, l);
        long[] ret = encrypt(srcLong, 0, l);
        return Bin.ltoi(ret);
    }

    @Override
    public long[] encrypt(long[] src, int offset, int length) {
        long[] ret = new long[length];
        int of = 0;
        while (length > of) {
            long[] x = encrypt(src, offset);
            System.arraycopy(x, 0, ret, of, x.length);
            offset += x.length;
            of += x.length;
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int l = length / 8;
        long[] srcLong = new long[l];

        Bin.btol(src, offset, srcLong, l);
        long[] ret = decrypt(srcLong, 0, l);
        return Bin.ltob(ret);
    }

    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int l = length / 2;
        long[] srcLong = new long[l];

        Bin.itol(src, offset, srcLong, l);
        long[] ret = decrypt(srcLong, 0, l);
        return Bin.ltoi(ret);
    }

    @Override
    public long[] decrypt(long[] src, int offset, int length) {
        long[] ret = new long[length];
        int of = 0;
        while (length > of) {
            long[] x = decrypt(src, offset);
            System.arraycopy(x, 0, ret, of, x.length);
            offset += x.length;
            of += x.length;
        }
        return ret;
    }

    @Override
    public void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        long[] srcInt = new long[length / 8];

        Bin.btol(src, offset, srcInt, length / 8);
        long[] ret = encrypt(srcInt, 0, length / 8);
        Bin.ltob(ret, dst, doffset);
    }

    @Override
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        long[] srcInt = new long[length / 8];

        Bin.btol(src, offset, srcInt, length / 8);
        long[] ret = decrypt(srcInt, 0, length / 8);
        Bin.ltob(ret, dst, doffset);
    }
}
