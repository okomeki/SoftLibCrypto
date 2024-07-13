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
package net.siisise.security.mac;

import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.lang.ParamThread;

/**
 * GCM 内部用GHASH.
 * 一般的に利用できる暗号化ハッシュ関数ではない.
 *
 */
public class GHASH implements MAC {

    // hash subkey Cache
    private final long[] HCa = new long[64];
    private final long[] HCb = new long[64];
    private final long[] HCc = new long[64];
    private final long[] HCd = new long[64];
    private long[] y;

    private Packet pool;
    // AAD length
    private Packet lens;
    private long alen;
    
    ParamThread th;

    public GHASH() {
    }

    /**
     * @param H hash subkey
     */
    @Override
    public void init(byte[] H) {
        init(Bin.btol(H), new byte[0]);
    }

    public void init(long[] H) {
        pool = new PacketA();
        lens = new PacketA();
        buildHCache(H);
        y = new long[H.length];
    }

    /**
     * 初期値っぽいもの
     *
     * @param H hash subkey
     * @param a 暗号化しない部分
     */
    public void init(long[] H, byte[] a) {
        pool = new PacketA();
        lens = new PacketA();
        buildHCache(H);
        y = new long[H.length];
        aad(a);
    }

    /**
     * Hの乗算結果をキャッシュして4倍くらい高速化.
     * @param H 
     */
    private void buildHCache(long[] H) {
        long[] x = H;
        for (int i = 0; i < 64; i++) {
            HCa[i] = x[0];
            HCb[i] = x[1];
            x = GF_x(x);
        }
        for (int i = 0; i < 64; i++) {
            HCc[i] = x[0];
            HCd[i] = x[1];
            x = GF_x(x);
        }
    }
    
    /**
     * H を維持したまま他を消す.
     */
    public void clear() {
        y = new long[y.length];
    }
    
    public void aad(byte[] a) {
        alen = 0;
        update(a, 0, a.length);
        blockClose();
    }

    private static final long CONST_RB = 0xe100000000000000l;

    private long[] GF_x(long[] s) {
        long[] r = Bin.shr(s);
        r[0] ^= (s[1] & 1) * CONST_RB;
        return r;
    }

    /**
     * y にブロックを y M_n
     *
     * @param x ブロック列っぽく
     */
    private void xorMul(byte[] x) {
        Bin.xorl(y, x, 0, y.length);
        YmulH();
    }

    /**
     * 128bit固定GF ビット順が逆 y・H.
     * 変態演算なのでメモリ食うかも
     * y・H
     */
    private void YmulH() {
        long b = 0;
        long c = 0;
        
        long t = y[0];
        long u = y[1];
        for (int i = 0; i < 64; i++) {
            if (t < 0) {
                b ^= HCa[i];
                c ^= HCb[i];
            }
            t<<=1;
            if (u < 0) {
                b ^= HCc[i];
                c ^= HCd[i];
            }
            u<<=1;
        }
        y[0] = b;
        y[1] = c;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        alen += length;
        pool.write(src, offset, length);
        thread();
    }

    /**
     * MAC計算用別スレッドが停止していたら走らせる.
     */
    void thread() {
        ParamThread t = th;
        if ( t == null || !t.isAlive()) {
            try {
                th = new ParamThread(this, "q");
                th.start();
            } catch (NoSuchMethodException ex) {
                throw new IllegalStateException(ex);
            }
        }
    }

    /**
     * MAC計算スレッド.
     * 別スレッドにするだけ.
     */
    public void q() throws java.lang.SecurityException {
        byte[] d = new byte[16];
        while (pool.size() >= 16) {
            pool.read(d);
            xorMul(d);
        }
        th = null;
    }

    private void blockClose() {
        Thread t = th;
        if ( t != null ) {
            try {
                t.join();
            } catch (InterruptedException ex) {
                throw new IllegalStateException(ex);
            }
        }
        
        int ps = pool.size();
        if (ps > 0) { // padding
            pool.write(new byte[16 - ps]);
            xorMul(pool.toByteArray());
        }

        lens.write(Bin.toByte(alen * 8));
        alen = 0;
    }

    /**
     *
     * @return tag
     */
    @Override
    public byte[] sign() {
        blockClose();
        xorMul(lens.toByteArray());
        return Bin.ltob(y);
    }

    @Override
    public int getMacLength() {
        return 128 / 8;
    }

}
