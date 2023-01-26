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
package net.siisise.security.digest;

import java.security.MessageDigest;
import net.siisise.security.PacketS;

/**
 * SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions (FIPS
 * PUB 202).
 * Secure Hash Algorithm-3 (SHA-3) family.
 * w=64 (long) で最適化したもの
 * ビット反転で作ってしまったもの
 */
public class SHA3B extends MessageDigest {

    protected PacketS pac;
    // bit
    protected long length;

    long[] a = new long[5 * 5];

    // ハッシュ長
    protected int n;
    // キャパシティ
//    protected int c;
    static final int l = 6;
    protected static final int w = 1 << l; // 2^l bit l = 6
    // 入出力分割ビット数?
    protected int r;
    protected int R;

    /**
     * r は 1152,1088,832,576
     *
     * @param n 224,256,384,512
     */
    public SHA3B(int n) {
        super("SHA3-" + n);
        this.n = n;
        engineReset();
    }

    @Override
    protected void engineReset() {
        int c = 2 * n; // キャパシティ 224が32の倍数なので倍
        //w = 64;
        // 200 - 56,64,96,128 * 8
        r = 5 * 5 * w - c; // 1600-c 448,512,768,1024 
        // R = 25 - 7,8,12,16 18,17,13,9
        R = r / 64;
        pac = new PacketS();
        length = 0;
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    static final long ROTR(final long x, final long n) {
        return (x >>> n) | (x << (64 - n));
    }

    /**
     * 3.2.1.
     * Algorithm 1
     * @param a A
     * @return A'
     */
    static final long[] Θ(long[] a) {
        long[] ad = new long[25];

        long[] c = new long[5];
        long[] d = new long[5];
        // 3.2.1 Θ
        // Step 1.
        for (int x = 0; x < 5; x++) {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        // Step 2.
        for (int x = 0; x < 5; x++) {
            d[x] = c[(x + 4) % 5] ^ ROTR(c[(x + 1) % 5], 1);
        }
        // Step 3.
        for (int b = 0; b < 25; b++) {
            int x = b % 5;
            ad[b] = a[b] ^ d[x];
        }
        return ad;
    }

    /**
     * 3.2.2
     * Algorithm 2
     * @param a
     * @return 
     */
    static final long[] ρ(long a[]) {
        // 3.2.2. ρ
        long[] ad = new long[25];
        ad[0] = a[0];
        int x = 1;
        int y = 0;
        for (int t = 0; t < 24; t++) {
            ad[x + y * 5] = ROTR(a[x + y * 5], ((t + 1) * (t + 2) / 2) % w);
            int nx = y;
            y = (2 * x + 3 * y) % 5;
            x = nx;
        }
        return ad;
    }

    /**
     * Algorithm 3.
     *
     * @param a
     * @return
     */
    static final long[] π(long a[]) {
        // 3.2.3 π
        long[] ad = new long[25];
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                ad[x + 5*y] = a[((x + 3*y) % 5) + 5*x];
            }
        }
        return ad;
    }

    /**
     * 3.2.4. Algorithm 4
     *
     * @param a
     * @return
     */
    static final long[] χ(long b[]) {
        long[] ad = new long[25];
        // 3.2.4 χ
        for (int y = 0; y < 5; y++) {
            for (int x = 0; x < 5; x++) {
                ad[x + y*5] = b[x + y*5] ^ ((~b[((x+1) % 5) + y*5]) & b[((x+2) % 5) + y*5]);
            }
        }
        return ad;
    }

    /**
     * Algorithm 5. 配列にしてもいい
     */
    static boolean rc(int t) {
        if (t % 255 == 0) {
            return true;
        }
        int R = 0x80;
        for (int i = 1; i <= t % 255; i++) {
//            R = 0 | R; // 9bit?
            R = (R & 0xe3) | ((R & 0x11c) ^ ((R & 1) * 0x11c));
            R >>>= 1;
        }
        return (R & 0x80) != 0;
    }

    /**
     * Algorithm 6.
     *
     * @param a
     * @param ir
     * @return
     */
    static final long[] ι(long a[], int ir) {
        long[] ad = new long[25];
        // 1.
        System.arraycopy(a,0,ad,0,25);
        // 2.
        long RC = 0;
        // 3.
        for (int j = 0; j <= l; j++) { // l = 6
            boolean td = rc(j + 7 * ir);
// 2^j - 1
// 0 1-1 0
// 1 2-1 1
// 2 4-1 3
// 3 8-1 7
// 4 16-1 15
// 5 32-1 31
// 6 64-1 63
//
//            RC |= td ? (1l << ((1<<j) -1)) : 0;
            RC |= td ? (1l << (64 - (1<<j))) : 0;
        }
        System.out.println("RC" + ir + ":" + Long.toHexString(RC));
        // 4.
        ad[0] ^= RC;
        // 5.
        return ad;
    }

    static final long[] tr(long[] src) {
        String l;
        for (int i = 0; i < 25; i++) {
            l = "000000000000000" + Long.toHexString(src[i]);
            l = l.substring(l.length() - 16);
            System.out.println(i % 5 + "," + i / 5 + ":" + l);
        }
        System.out.println("-");
        return src;
    }

    static final long[] rnd(long[] a, int ir) {
        return ι(χ(π(ρ(Θ(a)))), ir);
    }

    /**
     * 
     * @param s Aに変換済み
     * @param nr
     * @return A' S'には変換しない
     */
    final long[] keccak_p(long[] s, int nr) {

        for (int ir = 12 + 2 * l - nr; ir <= 12 + 2 * l - 1; ir++) {
            System.out.println("Rnd");
            s = rnd(s, ir);
            //a = ι(χ(π(ρ(Θ(a)))), ir);
        }
        return s;
    }

    final long[] keccak_f(long[] s) {
        return keccak_p(s, 12 + 2*l);
    }

    /**
     * Algorithm 8
     * @param b
     * @return 
     */
    byte[] sponge(byte[] b) {
        for (int c = 0; c < R; c++) {
            long n = 0;
            for (int j = 0; j < 8; j++) {
                n |= (((long) b[8 * c + j] & 0xff)) << ((7 - j) * 8);
            }
            a[c] ^= n;
        }
        a = keccak_f(a);

        byte[] o = new byte[R * 8];
        for (int c = 0; c < R; c++) {
            for (int j = 0; j < 8; j++) {
                o[c * 8 + j] = (byte) (a[c] >>> ((7 - j) * 8));
            }
        }
        return o;
    }
    
    byte[] keccak(byte[] m) {
        return sponge(m);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        pac.write(input, offset, len);
        length += len * 8l;

        byte[] dd = new byte[R * 8];
        while (pac.length() >= R * 8) {
            pac.read(dd);
            sponge(dd);
        }
    }

    @Override
    protected byte[] engineDigest() {

        long len = length;

        // padding バイト長で計算
        int rblen = R * 8;
        int padlen = rblen - (int) ((len / 8 + 1) % rblen) + 1;
        byte[] pad = new byte[padlen];
        pad[0] |= 0x60;
        pad[padlen - 1] |= 0x01;

        engineUpdate(pad, 0, pad.length);
//        byte[] rpad = new byte[R * 8];
//        byte[] rr;
        byte[] rr = new byte[R * 8];
        for (int c = 0; c < R; c++) {
            for (int j = 0; j < 8; j++) {
                rr[c * 8 + j] = (byte) (a[c] >>> ((7 - j) * 8));
            }
        }
//        rr = sponge(rpad);
        byte[] r = new byte[n / 8];
        System.arraycopy(rr, 0, r, 0, n / 8);
        engineReset();
        return r;
    }
}
