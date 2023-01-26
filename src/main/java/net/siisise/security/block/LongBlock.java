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

/**
 *
 */
public abstract class LongBlock extends BaseBlock {

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 64;
        long[] block = new long[bl];
        btol(src, offset, block, bl);
        return ltob(encrypt(block, 0));
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        int bl = getBlockLength() / 64;
        long[] block = new long[bl];
        itol(src, offset, block, bl);
        return ltoi(encrypt(block, 0));
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 64;
        long[] block = new long[bl];
        btol(src, offset, block, bl);
        return ltob(decrypt(block, 0));
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        int bl = getBlockLength() / 64;
        long[] block = new long[bl];
        itol(src, offset, block, bl);
        return ltoi(decrypt(block, 0));
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int l = length / 8;
        long[] srcLong = new long[l];

        btol(src, offset, srcLong, l);
        long[] ret = encrypt(srcLong, 0, l);
        return ltob(ret);
    }

    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        int l = length / 2;
        long[] srcLong = new long[l];

        itol(src, offset, srcLong, l);
        long[] ret = encrypt(srcLong, 0, l);
        return ltoi(ret);
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

        btol(src, offset, srcLong, l);
        long[] ret = decrypt(srcLong, 0, l);
        return ltob(ret);
    }

    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int l = length / 2;
        long[] srcLong = new long[l];

        itol(src, offset, srcLong, l);
        long[] ret = decrypt(srcLong, 0, l);
        return ltoi(ret);
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
        
        btol(src,offset,srcInt,length/8);
        long[] ret = encrypt(srcInt, 0, length/8);
        ltob(ret, dst, doffset);
    }

    @Override
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        long[] srcInt = new long[length / 8];
        
        btol(src,offset,srcInt,length/8);
        long[] ret = decrypt(srcInt, 0, length/8);
        ltob(ret, dst, doffset);
    }
}
