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
 * Output Feedback.
 * ストリームにも転用可能. (OFB8とかいうらしい)
 */
public final class OFB extends StreamMode {

    public OFB(Block block, byte[] key, byte[] iv) {
        super(block);
        init(key, iv);
    }

    @Override
    public void init(byte[]... key) {
        byte[][] nkey = new byte[key.length - 1][];
        System.arraycopy(key,0,nkey,0,key.length - 1);
        super.init(nkey);
        byte[] iv = key[key.length - 1];
        vector = new byte[getBlockLength() / 8];
        System.arraycopy(iv, 0, vector, 0, vector.length > iv.length ? iv.length : vector.length);
        next();
    }

    void next() {
        vector = block.encrypt(vector, 0);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int l = vector.length - this.offset;
        byte[] ret = new byte[length];
        int ro = 0;
        while (length > 0) {
            if (l > length) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                ret[ro++] = (byte) (vector[this.offset++] ^ src[offset++]);
                length--;
            }
            if (this.offset >= vector.length) {
                this.offset = 0;
                l = vector.length;
                next();
            }
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        byte[] nv = block.encrypt(vector, 0);
        byte[] ret = vector; // 配列の使い回し

        for (int i = 0; i < vector.length; i++) {
            ret[i] ^= src[offset + i];
        }

        vector = nv;
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return encrypt(src, offset);
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
