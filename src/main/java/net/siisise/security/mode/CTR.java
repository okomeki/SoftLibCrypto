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

import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.security.block.Block;

/**
 * Counter.
 * ivは適当な実装
 * ノンスとブロック番号を分けずに全部カウントするので隙なし.
 */
public class CTR extends StreamMode {

    Packet xp;

    public CTR(Block b) {
        super(b);
    }
    
    /**
     * 
     * @param b 暗号またはハッシュ関数
     * @param key
     * @param iv counter の初期値 - 1を含む長さで
     */
    public CTR(Block b, byte[] key, byte[] iv) {
        super(b);
        init(key, iv);
    }

    /**
     * 初期化 暗号key と IV.
     * 暗号に渡すパラメータ + CTR IV の形を取ってみた.
     * IV は毎回使い捨てること.
     * 充分な位置でカウントするのでも可.
     * 例 |固体固定値|初期乱数+カウント|ブロック番号|
     * @param params (block パラメータ),CTR iv
     */
    @Override
    public void init(byte[]... params) {
        super.init(in(1,params));

        int vlen = block.getBlockLength() / 8;
        byte[] vecsrc = params[params.length - 1];
        // iv
        byte[] v = new byte[vlen];
        System.arraycopy(vecsrc, 0, v, 0, Math.min(vecsrc.length, v.length));
        vectori = btoi(v);

        xp = new PacketA();
        next();
    }

    void next() {
        // カウントするだけ
        int x = vectori.length;
        do {
            x--;
            vectori[x]++;
        } while (vectori[x] == 0 && x != 0);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        byte[] ret = itob(block.encrypt(vectori, 0));
        for (int i = 0; i < ret.length; i++) {
            ret[i] ^= src[offset + i];
        }
        next();
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return encrypt(src, offset);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int rl = length - xp.size();
        for ( int i = 0; i < rl; i+= 16 ) { // 並列化すると速いかも
            xp.write(itob(block.encrypt(vectori,0)));
            next();
        }
        byte[] ret = new byte[src.length];
        xp.read(ret);
        for (int i = 0; i < ret.length; i++ ) {
            ret[i] ^= src[offset+i];
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        int[] ret = block.encrypt(vectori, 0);
        for (int i = 0; i < ret.length; i++ ) {
            ret[i] ^= src[offset + i];
        }
        next();
        return ret;
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        return encrypt(src, offset);
    }
}
