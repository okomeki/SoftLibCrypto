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

/**
 * GCM 内部用GHASH.
 * 一般的に利用できる暗号化ハッシュ関数ではない.
 * 
 */
public class GHASH implements MAC {
    
    // hash subkey
    private long[] H;
    long[] y;

    Packet pool;
    // AAD length
    Packet lens;
    long alen;

    public GHASH() {
    }
    
    /**
     * @param H hash subkey
     */
    @Override
    public void init(byte[] H) {
        init(H, new byte[0]);
    }

    /**
     * 初期値っぽいもの
     * @param H hash subkey
     * @param a 暗号化しない部分
     */
    public void init(byte[] H, byte[] a) {
        pool = new PacketA();
        lens = new PacketA();
        this.H = Bin.btol(H);
        y = new long[this.H.length];
        alen = 0;
        update(a, 0, a.length);
        blockClose();
    }

    /**
     * y にブロックを y M_n
     * @param x ブロック列っぽく
     * @param o 位置
     */
    private void xorMul(byte[] x, int o) {
        Bin.xorl(y, x, o, y.length);
        y = GF_mul(y,H);
    }

    private void xorMul(byte[] x) {
        Bin.xorl(y, x, 0, y.length);
        y = GF_mul(y,H);
    }

    /**
     * 128bit固定GF ビット順が逆 a・b
     * @param a
     * @param b
     * @return a・b
     */
    private long[] GF_mul(long[] a, long[] b) {
        long[] r = new long[2];
        for ( int j = 0; j < 2; j++ ) {
            long t = a[j];
            for ( int i = 63; i >= 0; i-- ) {
                if ( ((t >>> i) & 1) != 0 ) {
                    Bin.xorl(r, b);
                }
                long x = (b[1] & 1) * CONST_RB;
                b = Bin.shr(b);
                b[0] ^= x;
            }
        }
        return r;
    }
    
    static final long CONST_RB = 0xe100000000000000l;
    
    boolean isZero(long[] a) {
        for (int i = 0; i < a.length; i++) {
            if ( a[i] != 0 ) return false;
        }
        return true;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        alen += length;
        int ps = pool.size();
        if ( ps + length < 16 ) {
            pool.write(src, offset, length);
            return;
        } else if ( ps > 0 ) {
            int l = 16 - ps;
            pool.write(src, offset, l);
            offset += l;
            length -= l;
            xorMul(pool.toByteArray());
        }
        while ( length >= 16 ) {
            xorMul(src, offset);
            offset += 16;
            length -= 16;
        }
        pool.write(src, offset, length);
    }
    
    private void blockClose() {
        if ( pool.size() > 0 ) { // padding
            pad();
        }

        lens.write(Bin.toByte(alen*8));
        alen = 0;
    }
    
    private void pad() {
        pool.write(new byte[16 - pool.size()]);
        xorMul(pool.toByteArray());
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
        return H.length;
    }
    
}
