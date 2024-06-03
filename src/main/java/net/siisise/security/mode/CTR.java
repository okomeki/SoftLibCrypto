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
import net.siisise.lang.Bin;
import net.siisise.security.block.Block;

/**
 * Counter.
 * ivは適当な実装
 * ノンスとブロック番号を分けずに全部カウントするので隙なし.
 */
public class CTR extends LongStreamMode {

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
        vectorl = Bin.btol(v);

        xp = new PacketA();
//        next();
    }

    void next() {
        // カウントするだけ
        int x = vectorl.length;
        do {
            x--;
            vectorl[x]++;
        } while (vectorl[x] == 0 && x != 0);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        byte[] ret = Bin.ltob(block.encrypt(vectorl, 0));
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
    public long[] encrypt(long[] src, int offset) {
        long[] ret = block.encrypt(vectorl, 0);
        for (int i = 0; i < ret.length; i++ ) {
            ret[i] ^= src[offset + i];
        }
        next();
        return ret;
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        return encrypt(src, offset);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int rl = xp.size();
        int roffset = 0;
//        byte[] ret = Arrays.copyOfRange(src, offset, length);
        byte[] ret = new byte[length];
        if ( rl > 0 ) {
            byte[] tmp = new byte[rl];
            roffset = xp.read(tmp);
            for ( int i = 0; i < tmp.length; i++ ) {
                ret[i] ^= tmp[i];
            }
            offset += roffset;
            length -= roffset;
        }
        int vl = vectorl.length * 8;
        
        while ( length >= vl ) { // 並列化すると速いかも
            long[] tmp = block.encrypt(vectorl, 0);
//            byte[] tmp = Bin.ltob(block.encrypt(vectorl, 0));
            long[] tmp2 = Bin.btol(src, offset, vectorl.length);
            tmp2[0] ^= tmp[0];
            tmp2[1] ^= tmp[1];
            Bin.ltob(tmp2,ret,roffset);
            offset += vl;
            roffset += vl;
//            for ( int j = 0; j < vl; j++ ) {
//                ret[roffset++] ^= tmp[j/8] >> (((255-j) % 8) * 8);
//                ret[roffset++] ^= tmp[j];
//            }
            length -= vl;
//            xp.write(Bin.ltob(block.encrypt(vectorl,0)));
            next();
        }
        if ( length > 0 ) {
            byte[] tmp = Bin.ltob(block.encrypt(vectorl, 0));
            for ( int i = 0; i < length; i++ ) {
                ret[roffset++] ^= tmp[i];
            }
            xp.write(tmp, length, tmp.length - length);
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }
}
