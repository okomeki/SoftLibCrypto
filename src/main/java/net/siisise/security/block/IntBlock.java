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
 * ブロック暗号に対応する.
 * byte[]は遅いのでint[]で高速化する
 * encrypt(src, offset) の実装が必要
 */
public abstract class IntBlock extends BaseBlock {

    /**
     * byte列をint列に変換して1ブロック暗号化.
     * サイズは暗号に依存するため指定しない.
     *
     * @param src 平文ブロック
     * @param offset 位置
     * @return 暗号ブロック
     */
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 32;
        return Bin.itob(encrypt(Bin.btoi(src, offset, bl), 0));
    }

    /**
     * long列で1ブロック暗号化.
     * サイズは暗号に依存するため指定しない.
     *
     * @param src 平文ブロック
     * @param offset 位置
     * @return 暗号ブロック
     */
    @Override
    public long[] encrypt(long[] src, int offset) {
        int bl = getBlockLength() / 32;
        return Bin.itol(encrypt(Bin.ltoi(src, offset, bl), 0));
    }

    /**
     * int列に変換して1ブロック復号.
     *
     * @param src 暗号ブロック
     * @param offset 位置
     * @return 平文ブロック
     */
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 32;
        return Bin.itob(decrypt(Bin.btoi(src, offset, bl), 0));
    }

    /**
     * 1ブロック復号.
     *
     * @param src 暗号ブロック
     * @param offset 位置
     * @return 平文ブロック
     */
    @Override
    public long[] decrypt(long[] src, int offset) {
        int bl = getBlockLength() / 32;
        return Bin.itol(decrypt(Bin.ltoi(src, offset, bl), 0));
    }

    /**
     * 暗号化.
     * ストリームモードでも使用する
     * 4バイト境界に依存するためPaddingが必要な場合やストリームモードはそのまま使わない方がいいかも.
     *
     * @param src 平文データ列
     * @param offset 符号化位置
     * @param length データ長
     * @return 暗号列
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int[] srcInt = new int[length / 4];

        Bin.btoi(src, offset, srcInt, length / 4);
        int[] ret = encrypt(srcInt, 0, length / 4);
        return Bin.itob(ret);
    }

    /**
     * 暗号化.
     * @param src 平文
     * @param offset 位置
     * @param length サイズ
     * @return 暗号文
     */
    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        int[] ret = new int[length];
        int of = 0;
        while (length > of) {
            int[] x = encrypt(src, offset);
            System.arraycopy(x, 0, ret, of, x.length);
            offset += x.length;
            of += x.length;
        }
        return ret;
    }

    @Override
    public long[] encrypt(long[] src, int offset, int length) {
        int[] srcInt = new int[length * 2];

        Bin.ltoi(src, offset, srcInt, length * 2);
        int[] ret = encrypt(srcInt, 0, length * 2);
        return Bin.itol(ret);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int[] srcInt = new int[length / 4];

        Bin.btoi(src, offset, srcInt, srcInt.length);
        int[] ret = decrypt(srcInt, 0, srcInt.length);
        return Bin.itob(ret);
    }

    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int[] ret = new int[length];
        int of = 0;
        while (length > of) {
            int[] x = decrypt(src, offset);
            System.arraycopy(x, 0, ret, of, x.length);
            offset += x.length;
            of += x.length;
        }
        return ret;
    }

    @Override
    public long[] decrypt(long[] src, int offset, int length) {
        int[] srcInt = new int[length * 2];

        Bin.ltoi(src, offset, srcInt, srcInt.length);
        int[] ret = decrypt(srcInt, 0, srcInt.length);
        return Bin.itol(ret);
    }

    /**
     * 暗号化.
     *
     * @param src 元ブロック列
     * @param offset 符号化位置
     * @param dst 暗号化先
     * @param doffset 先符号化位置
     * @param length 長さ
     */
    @Override
    public void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        int[] srcInt = new int[length / 4];

        Bin.btoi(src, offset, srcInt, length / 4);
        int[] ret = encrypt(srcInt, 0, length / 4);
        Bin.itob(ret, dst, doffset);
    }

    @Override
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        int[] srcInt = new int[length / 4];

        Bin.btoi(src, offset, srcInt, length / 4);
        int[] ret = decrypt(srcInt, 0, length / 4);
        Bin.itob(ret, dst, doffset);
    }
}
