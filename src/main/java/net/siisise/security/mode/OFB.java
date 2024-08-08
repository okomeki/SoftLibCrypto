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

import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.block.Block;

/**
 * Output Feedback.
 * ストリームにも転用可能. (OFB8とかいうらしい)
 * CTR とほぼ同じ.
 */
public final class OFB extends StreamMode {

    Packet xp;

    public OFB(Block block) {
        super(block);
    }
    
    public OFB(Block block, byte[] key, byte[] iv) {
        super(block);
        init(key, iv);
    }

    /**
     * 
     * @param params key, iv
     */
    @Override
    public void init(byte[]... params) {
        super.init(in(1,params));
        byte[] iv = params[params.length - 1];
        vector = new byte[getBlockLength() / 8];
        System.arraycopy(iv, 0, vector, 0, vector.length > iv.length ? iv.length : vector.length);
        xp = new PacketA();
    }

    void next() {
        vector = block.encrypt(vector, 0);
        xp.write(vector);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int size = xp.size();
        for (int i = size; i < length; i+= vector.length) {
            next();
        }
        byte[] ret = new byte[length];
        xp.read(ret);
        for (int i = 0; i < length; i++ ) {
            ret[i] ^= src[offset + i];
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

        for (int i = 0; i < ret.length; i++) {
            ret[i] ^= src[offset++];
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
        int[] ret = Bin.btoi(vector);

        for (int i = 0; i < ret.length; i++) {
            ret[i] ^= src[offset + i];
        }

        vector = block.encrypt(vector, 0);
        return ret;
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        return encrypt(src,offset);
    }

    @Override
    public long[] encrypt(long[] src, int offset) {
        long[] ret = Bin.btol(vector);

        for (int i = 0; i < ret.length; i++) {
            ret[i] ^= src[offset + i];
        }

        vector = block.encrypt(vector, 0);
        return ret;
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        return encrypt(src,offset);
    }
}
