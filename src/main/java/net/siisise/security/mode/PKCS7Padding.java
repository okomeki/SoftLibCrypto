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

import java.util.Arrays;
import net.siisise.security.block.Block;

/**
 * PKCS #7 らしい Padding
 * 繰り返しは想定していない.
 */
public class PKCS7Padding extends BlockMode {
    
    int blockLen;
    
    public PKCS7Padding(Block block) {
        super(block);
        blockLen = (block.getBlockLength() + 7) / 8;
    }

    /**
     * パディング付き
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int mod = length % blockLen;
        int pad = blockLen - mod;
        
        byte[] dst = new byte[length + pad];
        encrypt(src, offset, dst, 0, length);
        return dst;
    }

    /**
     * パディング付き
     * @param src message
     * @param offset
     * @param dst 予測されるpaddingを含むサイズ
     * @param doffset
     * @param length 
     */
    @Override
    public void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        int mod = length % blockLen;
        int pad = blockLen - mod;

        byte[] bl = new byte[blockLen];
        block.encrypt(src, offset, dst, doffset, length - mod); // padding のない部分
        System.arraycopy(src, length - mod, bl, 0, mod);
        byte f = (byte)pad;
        Arrays.fill(bl, mod, blockLen, f);
        block.encrypt(bl, 0, dst, doffset + length - mod, blockLen);
    }

    /*
     * パディング付き
     */
    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        int mod = length % (blockLen / 4);
        int pad = (blockLen / 4) - mod;
        
        int[] dst = new int[length + pad];
        encrypt(src, offset, dst, 0, length);
        return dst;
    }

    /**
     * パディング付き
     * @param src
     * @param offset
     * @param dst
     * @param doffset
     * @param length 
     */
    public void encrypt(int[] src, int offset, int[] dst, int doffset, int length) {
        int intLen = blockLen / 4;
        int mod = length % (intLen);
        int pad = intLen - mod;

        int[] st = block.encrypt(src, offset, length - mod);
        System.arraycopy(st, 0, dst, doffset, length - mod);
        int[] bl = new int[intLen];
        System.arraycopy(src, length - mod, bl, 0, mod);
        int f = pad * 0x04040404;
        Arrays.fill(bl, mod, intLen, f);
        bl = block.encrypt(bl,0);
        System.arraycopy(bl, 0, dst, doffset + length - mod, intLen);
    }

    /**
     * パディングしない.
     * @deprecated 使えない
     */
    @Override
    @Deprecated
    public byte[] encrypt(byte[] src, int offset) {
        return block.encrypt(src, offset);
    }

    /**
     * パディングしない.
     * @deprecated 使えない
     */
    @Override
    @Deprecated
    public int[] encrypt(int[] src, int offset) {
        return block.encrypt(src, offset);
    }

    /**
     * パディング解除
     * @param src 暗号文
     * @param offset 位置
     * @param length サイズ
     * @return 平文
     */
    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        byte[] dec = block.decrypt(src, offset, length);
        int len = dec.length - ((int)dec[dec.length - 1]);
        byte[] dst = new byte[len];
        System.arraycopy(dec, 0, dst, 0, len);
        return dst;
    }

    /**
     * 正確な長さが出せないので使えない
     * @deprecated 
     * @param src 暗号文
     * @param offset 開始位置
     * @param dst 平文
     * @param doffset 位置
     * @param length 
     */
    @Override
    @Deprecated
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
//        block.decrypt(src, offset, dst, doffset, length);
        throw new UnsupportedOperationException("正確な長さが出せない.");
    }

    /**
     * 4バイト境界前提でパディング解除する
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int[] dec = block.decrypt(src, offset, length);
        int len = dec.length - (((int)dec[dec.length - 1] & 0xff) / 4);
        int[] dst = new int[len];
        System.arraycopy(dec, 0, dst, 0, len);
        return dst;
    }

    /**
     * パディングしない
     * @deprecated 使えない
     */
    @Override
    @Deprecated
    public byte[] decrypt(byte[] src, int offset) {
        return block.decrypt(src, offset);
    }

    /**
     * パディングしない
     * @deprecated 使えない
     */
    @Override
    @Deprecated
    public int[] decrypt(int[] src, int offset) {
        return block.decrypt(src, offset);
    }
    
    /**
     * パディングしない.
     * @deprecated 使えない
     */
    @Override
    @Deprecated
    public long[] decrypt(long[] src, int offset) {
        return block.decrypt(src, offset);
    }
    
}
