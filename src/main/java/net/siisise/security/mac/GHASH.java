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
import net.siisise.math.GF;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;

/**
 * GCM 内部用
 */
public class GHASH implements MAC {
    
    Block block;
    GF gf = new GF(128,GF.FF128);
    byte[] H;
    byte[] x;
    Packet pool;
    int alen;
    long blen;

    public GHASH(Block b) {
        block = b;
    }
    
    public GHASH() {
        block = new AES();
    }
    
    @Override
    public void init(byte[] key) {
        init(key, new byte[0]);
    }

    /**
     * x にブロックを x M_n
     * @param x 元
     * @param a ブロック列っぽく
     * @param n ブロック番号 1-
     */
    private void xorMul(byte[] a, int off) {
        for ( int i = 0; i < x.length; i++ ) {
            x[i] ^= a[off + i];
        }
        x = gf.mul(x,H);
    }

    private void xorMul(byte[] a) {
        for ( int i = 0; i < x.length; i++ ) {
            x[i] ^= a[i];
        }
        x = gf.mul(x,H);
    }

    /**
     * 初期値っぽいもの
     * @param key AES鍵
     * @param a 暗号化しない部分
     */
    public void init(byte[] key, byte[] a) {
        if ( key != null ) {
            block.init(key);
        }
        pool = new PacketA();
    
        alen = a.length;
        blen = 0;
        ghash1(a);
    }

    void ghash1(byte[] a) {
        int m = (a.length + 15) / 16; // 収納ブロック数 0のとき0 1-16のとき1
        x = new byte[16]; // i = 0
        H = block.encrypt(x);
        for ( int i = 0; i < m - 1; i++ ) { // i = 1 to m -1
            xorMul(a,i*16);
        }
        // i = m ToDo: m = 0 のとき?
        PacketA p = new PacketA();
        p.write(a, m*16, a.length % 16);
        p.write(new byte[16 - (a.length % 16)]);
        xorMul(p.toByteArray());
    }

    /**
     * 一括の場合
     * @param c
     * @return 
     */
    byte[] ghash2(byte[] c) {
        // H Zero を暗号にかけたもの
        int n = (c.length + 15) / 16;
        // i = m + 1 to m + n - 1
        for (int i = 0; i < n - 1; i++ ) {
            xorMul(c,i*16);
        }
        Packet p = new PacketA();
        p.write(c, n * 16, c.length % 16 );
        p.write(new byte[16 - c.length % 16]);
        xorMul(p.toByteArray());

        p.write(Bin.toByte(alen * 8l));
        p.write(Bin.toByte(c.length * 8l));
        xorMul(p.toByteArray());
        return x;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        int l = Math.min(pool.size() - 16, length);
        blen += length;
        pool.write(src,offset,l);
        offset += l;
        length -= l;
        byte[] d = new byte[16];
        if (pool.length() > 16) {
            pool.read(d);
            xorMul(d);
        }
        while ( length > 16 ) {
            xorMul(src,offset);
            offset += 16;
            length -= 16;
        }
        pool.write(src,offset,length);
    }

    @Override
    public byte[] doFinal() {
        long n = (blen + 15) / 16;
        pool.dwrite(new byte[16 - pool.size()]);
        xorMul(pool.toByteArray());

        Packet p = new PacketA();
        p.dwrite(Bin.toByte(alen * 8l));
        p.dwrite(Bin.toByte(blen * 8l));
        xorMul(p.toByteArray());
        return x;
    }

    @Override
    public int getMacLength() {
        return block.getBlockLength() / 8;
    }
    
}
