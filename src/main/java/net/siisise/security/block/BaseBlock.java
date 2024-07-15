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
public abstract class BaseBlock implements Block {

    /**
     * 必要な初期値(鍵,IVなど)のビット長のめやす.
     * @return key bit length array
     */
    @Override
    public int[] getParamLength() {
        return new int[] { getBlockLength() };
    }

    /**
     * 暗号化.
     * @param src 元ブロック
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] src) {
        return encrypt(src, 0, src.length);
    }

    @Override
    public int[] encrypt(int[] src) {
        return encrypt(src, 0, src.length);
    }

    @Override
    public long[] encrypt(long[] src) {
        return encrypt(src, 0, src.length);
    }

    @Override
    public byte[] decrypt(byte[] src) {
        return decrypt(src, 0, src.length);
    }

    @Override
    public int[] decrypt(int[] src) {
        return decrypt(src, 0, src.length);
    }

    @Override
    public long[] decrypt(long[] src) {
        return decrypt(src, 0, src.length);
    }

    /**
     * 復号処理.
     * 
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int blen = getBlockLength() / 8;
        int len = length / blen;
        byte[] dec = new byte[length];
        byte[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }
    
    /**
     * 復号処理.
     * 
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int blen = getBlockLength() / 32;
        int len = length / blen;
        int[] dec = new int[length];
        int[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }

    @Override
    public long[] decrypt(long[] src, int offset, int length) {
        int blen = getBlockLength() / 64;
        int len = length / blen;
        long[] dec = new long[length];
        long[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }
    
    @Override
    public byte[] doFinalEncrypt() {
        return doFinalEncrypt(new byte[0]);
    }

    @Override
    public byte[] doFinalEncrypt(byte[] src) {
        return doFinalEncrypt(src, 0, src.length);
    }

    @Override
    public byte[] doFinalEncrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }

    @Override
    public byte[] doFinalDecrypt() {
        return doFinalDecrypt(new byte[0]);
    }

    @Override
    public byte[] doFinalDecrypt(byte[] src) {
        return doFinalDecrypt(src, 0, src.length);
    }

    @Override
    public byte[] doFinalDecrypt(byte[] src, int offset, int length) {
        return decrypt(src, offset, length);
    }
}
