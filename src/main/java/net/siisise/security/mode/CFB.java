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
 * Cipher Feedback.
 * ストリームにも転用可能 (CFB8とかいうらしい)
 * 復号処理の並列化が可能
 */
public final class CFB extends StreamMode {

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
        vectori = btoi(vector);
        vectori = block.encrypt(vectori, 0);
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
    public int[] encrypt(int[] src, int offset) {
        xor(vectori, src, offset, vector.length);
        int[] ret = vectori;
        vectori = block.encrypt(ret, 0);
        return ret;
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        int[] ret = vectori;
        xor(ret, src, offset, ret.length);
        vectori = block.encrypt(src, offset);
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
    public int[] encrypt(int[] src, int offset, int length) {
        int l = vectori.length - this.offset;
        int[] ret = new int[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                vectori[this.offset] ^= src[offset++];
                ret[ro++] = vectori[this.offset++];
                length--;
            }
            if (this.offset >= vectori.length) {
                this.offset = 0;
                vectori = block.encrypt(vectori, 0);
                l = vectori.length;
            }
        }
        return ret;
    }

    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int l = vectori.length - this.offset;
        int[] ret = new int[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                ret[ro++] = (byte) (vectori[this.offset + i] ^ src[offset + i]);
                vectori[this.offset++] = src[offset++];
                length--;
            }
            if (this.offset >= vectori.length) {
                this.offset = 0;
                vectori = block.encrypt(vectori, 0);
                l = vectori.length;
            }
        }
        return ret;
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
