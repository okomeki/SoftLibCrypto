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

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int mod = length % blockLen;
        int pad = blockLen - mod;
        
        byte[] dst = new byte[length + pad];
        encrypt(src, offset, dst, 0, length);
        return dst;
    }

    @Override
    public void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        int mod = length % blockLen;
        int pad = blockLen - mod;

        byte[] bl = new byte[blockLen];
        block.encrypt(src, offset, dst, doffset, length - mod);
        System.arraycopy(src, length - mod, bl, 0, mod);
        byte f = (byte)pad;
        Arrays.fill(bl, mod, blockLen, f);
        block.encrypt(bl, 0, dst, doffset + length - mod, blockLen);
    }

    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

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
     * @param src
     * @param offset
     * @param dst
     * @param doffset
     * @param length 
     */
    @Override
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
//        block.decrypt(src, offset, dst, doffset, length);
        throw new UnsupportedOperationException("正確な長さが出せない.");
    }

    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
