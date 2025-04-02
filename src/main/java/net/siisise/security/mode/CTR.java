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
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.lang.ParamThread;
import net.siisise.security.block.Block;

/**
 * Counter.
 * ivは適当な実装
 * ノンスとブロック番号を分けずに全部カウントするので隙なし.
 */
public class CTR extends LongStreamMode {

    Packet xp;
    Thread th;

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
     * IV ブロック番号まで含めても含めなくてもよい.
     *
     * @param params (block パラメータ),CTR IV
     */
    @Override
    public void init(byte[]... params) {
        super.init(in(1, params));

        int vlen = block.getBlockLength() / 8;
        byte[] vecsrc = params[params.length - 1];
        // iv
        byte[] v = new byte[vlen];
        System.arraycopy(vecsrc, 0, v, 0, Math.min(vecsrc.length, v.length));
        vectorl = Bin.btol(v);

        xp = new PacketA();
        thread();
    }

    /**
     *
     * @param len　ほしい長さ
     */
    public void cc(int len) {
        int size = xp.size();
        while (size < len && th != null) {
            xp.write(Bin.ltob(block.encrypt(vectorl, 0)));
            size += 16;
            next();
        }
        th = null;
    }

    /**
     * 
     * @param len ほしい長さ
     */
    void lcc(int len) {
        int size = xp.size();
        while (size < len) {
            xp.write(Bin.ltob(block.encrypt(vectorl, 0)));
            size += 16;
            next();
        }
    }

    void thread() {
        Thread t = th;
        if (t == null) {
            try {
                th = new ParamThread(this, "cc", 20000);
//            next();
            } catch (NoSuchMethodException ex) {
                throw new IllegalStateException(ex);
            }
        }
    }

    private void join() {
        Thread t = th;
        th = null;
        if (t != null) {
            try {
                t.join();
            } catch (InterruptedException ex) {
                throw new IllegalStateException(ex);
            }
        }
    }
    
    private void join(int len) {
        Thread t = th;
        th = null;
        if (t != null) {
            try {
                t.join();
            } catch (InterruptedException ex) {
                throw new IllegalStateException(ex);
            }
        }
        lcc(len);
    }

    void next() {
        // カウントするだけ
        int x = vectorl.length;
        do {
            x--;
            vectorl[x]++;
        } while (vectorl[x] == 0 && x != 0);
    }

    /**
     * ブロックモード用.
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        byte[] ret = new byte[16];
        join(16);
        int s = xp.read(ret);
//        if ( s != 16 ) {
            //xp.backWrite(ret, 0, s);
//            ret = Bin.ltob(block.encrypt(vectorl, 0));
//            next();
//        }
        thread();
        for (int i = 0; i < ret.length; i++) {
            ret[i] ^= src[offset + i];
        }
        return ret;
    }

    /**
     * ブロックモード用.
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return encrypt(src, offset);
    }

    /**
     * ブロックモード用.
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public long[] encrypt(long[] src, int offset) {
        long[] ret;
        if ( xp.readable(16)) {
            byte[] r = new byte[16];
            xp.read(r);
            ret = Bin.btol(r);
        } else {
            ret = block.encrypt(vectorl, 0);
        }
        Bin.xorl(ret, src, offset, ret.length);
//        for (int i = 0; i < ret.length; i++) {
//            ret[i] ^= src[offset + i];
//        }
        next();
        return ret;
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        return encrypt(src, offset);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        join();
        int rl = xp.size();
        byte[] ret = Arrays.copyOfRange(src, offset, offset + length);
        int roffset = 0;
        if (rl > 0) {
            roffset = Math.min(rl, length);
            byte[] mask = new byte[roffset];
            xp.read(mask);
            for (int i = 0; i < roffset; i++) {
                ret[i] ^= mask[i];
            }
            length -= roffset;
        }
        int vl = vectorl.length * 8;

        while (length >= vl) { // 並列化すると速いかも
            long[] mask = block.encrypt(vectorl, 0);
            for (int j = 0; j < mask.length; j++) {
                for (int i = 7; i >= 0; i--) {
                    ret[roffset++] ^= mask[j] >>> (i * 8);
                }
            }
            length -= vl;
            next();
        }
        if (length > 0) {
            byte[] tmp = Bin.ltob(block.encrypt(vectorl, 0));
            for (int i = 0; i < length; i++) {
                ret[roffset++] ^= tmp[i];
            }
            xp.write(tmp, length, tmp.length - length);
            next();
        }
        thread();
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }
}
