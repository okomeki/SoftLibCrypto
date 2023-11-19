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

import java.util.Arrays;
import net.siisise.security.io.BlockOutputStream;

/**
 * Keccak-f[1600].
 * SHA-3のもと
 * cは2倍にしていいのか謎
 *
 * Keccak-f[b] {25, 50, 100, 200, 400, 800, 1600} のうち b = 1600 のもの
 * 固定値
 * SHA-3 l = 6; w = 64; b = 5*5*w = 1600
 * 可変値
 * c: capacity SHA-3では2*d, d: 出力ビット長, pad頭
 */
public class Keccak extends BlockMessageDigest {

    // 固定値
    private static final int l = 6;
    private static final int w = 1 << l; // 64
    // 固定箱
    private final long[] a = new long[5 * 5];

    // 出力ビット長
    private int d;

    // 入出力分割ビット数?
    private int r;
    private int R;

    static final long[] RC = new long[24];

    static {
        for (int ir = 0; ir < 24; ir++) {
            for (int j = 0; j <= l; j++) { // l = 6
                // little endian
                RC[ir] |= rc(j + 7 * ir) ? (1l << ((1 << j) - 1)) : 0;
            }
        }
    }

    private byte padstart;

    /**
     * Keccak[c](N,d).
     * c = 2*d の SHA-3相当
     *
     * @param d 出力ビット長 c=2*d
     */
    public Keccak(int d) {
        this(2 * d, d);
    }

    /**
     * 5.2. Specification of KECCAK[c].
     *
     * Keccak[c](N,d)
     * N 入力
     *
     * @param c キャパシティ b まで
     * @param d 出力ビット長 b まで
     */
    public Keccak(int c, int d) {
        this("Keccak[" + c + "](N," + d + ")", c, d, (byte) 0x01);
    }

    /**
     *
     * Keccak[c](N,d)
     * l = 6
     * SPONGE[KECCAK-p[1600,12+2l],pad10*1,1600-c]
     * N 入力
     *
     * @param name
     * @param c キャパシティ 2*d か d か固定
     * @param d 出力長
     * @param suffix paddingの前に付加するビット列 とKeccak padding先頭1ビットをまとめた値  頭ビットは下位
     */
    protected Keccak(String name, int c, int d, byte suffix) {
        super(name + d);
        this.d = d;
        r = 5 * 5 * w - c; // 1600-c 1152(448),1088(512),832(768),576(1024) 1344(256) 1088(512) 
        R = r / w;         // 25       18(448)   17(512)  13(768)   9(1024)   21(256)   17(512)
        padstart = suffix;
        engineReset();
    }

    @Override
    protected int engineGetDigestLength() {
        return d / 8;
    }

    /**
     * 出力長をあとで調整する.
     * 変更できないものもあるので注意.
     * getDigestLength にあわせたのでバイト単位.
     * @param length 出力バイト長
     */
    public void setDigestLength(int length) {
        d = length * 8;
    }

    /**
     * 入力を分割するサイズ
     * @return 
     */
    @Override
    public int getBitBlockLength() {
        return r;
    }

    @Override
    protected void engineReset() {
        pac = new BlockOutputStream(this);
        Arrays.fill(a, 0l);
    }

    /**
     * 左ローテート
     * little endian
     */
    private static long ROTL(final long x, final int n) {
        // d = d % w;
        return (x >>> (w - n)) | (x << n);
    }

    /**
     * Algorithm 5.
     * 事前計算可能
     * bitなので big endian で計算している
     */
    static boolean rc(int t) {
        if (t % 255 == 0) {
            return true;
        }
        int R = 0x80;
        for (int i = 1; i <= t % 255; i++) {
            R = (R & 0xe3) | ((R & 0x1c) ^ ((R & 1) * 0x11c));
            R >>>= 1;
        }
        return (R & 0x80) != 0;
    }

//    static final int[] rr = {0,300,171,21,78,28,276,3,45,253,1,6,153,136,210,91,36,10,15,120,190,55,231,105,66};
    static final int[] rr = {0, 44, 43, 21, 14, 28, 20, 3, 45, 61, 1, 6, 25, 8, 18, 27, 36, 10, 15, 56, 62, 55, 39, 41, 2};

    /**
     * 3.4 KECCAK-f
     * 3.3 KECCAK-p
     * Algorithm 7:
     * 3.2 Step Mappings
     * Algorithm 1: θ(A)
     * @param a Sっぽい
     */
    private void keccak_f(long[] a) {
        long[] ad = new long[25]; // 1600bit パターン

        for (int ir = 0; ir < 12 + 2 * l; ir++) {
            // 3.2.1 Algorithm 1: Θ(A)
            // Step 1.
            for (int x = 0; x < 5; x++) {
                ad[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }
            // Step 2.
            for (int x = 5; x < 10; x++) {
                ad[x] = ad[(x + 4) % 5] ^ ROTL(ad[(x + 1) % 5], 1);
            }
            // Step 3.
            for (int b = 0; b < 25; b++) {
                a[b] ^= ad[5 + b % 5];
            }
            // 3.2.2 Algorithm 2: ρ(A)
            // 3.2.3 Algorithm 3: π(A)
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    ad[x + y * 5] = ROTL(a[(y * 3 + x) % 5 + x * 5], rr[x + y * 5]);
                }
            }

            // 3.2.4 Algorithm 4: χ(A)
            for (int y = 0; y < 25; y += 5) {
                for (int x = 0; x < 5; x++) {
                    a[x + y] = ad[x + y] ^ ((~ad[((x + 1) % 5) + y]) & ad[((x + 2) % 5) + y]);
                }
            }
            // 3.2.5 algorithm 5: rc(t)
            a[0] ^= RC[ir];
        }
    }

    /**
     * 3.1.2 Converting Strings to State Arrays
     * A[x,y,z] = z ビット方向
     * 内から z,x,y の順でループ z は 0 が下位ビット
     * a を long[x + y * 5] としてbからデータを移すことにする
     * 3.1.3 Converting State Arrays to Strings
     * Lane(i,j) = a[i + j * 5] ビット並びは逆
     * Plane(j) = Lane(0,j) || Lane(1,j) || ...
     * S = Plane(0) || Plane(1) || ...
     * 
     * Algorithm 8
     *
     * @param b input / output
     */
    private void keccak(byte[] b, int offset) {
        // A[x,y,z] = S[w(5y+x)+z)
        int wb = w / 8;
        for (int c = 0; c < R; c++) {
            int of = offset + wb * c;
            for (int j = 0; j < wb; j++) {
                a[c] ^= (((long) b[of + j] & 0xff)) << (j * 8);
            }
        }
        keccak_f(a);
    }

    /**
     * pac から固定長で受け取るところ.
     * @param input
     * @param offset
     * @param len 
     */
    @Override
    public void blockWrite(byte[] input, int offset, int len) {
        keccak(input, offset);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        pac.write(input, offset, len);
    }
    
    /**
     * Algorithm 8
     * @param d 出力長 bit
     * @return dサイズになったn
     */
    private byte[] sponge(int d) {
        byte[] pad = pad10x1();
        pac.write(pad);
        
        byte[] ret = new byte[(d + 7) / 8];
        int offset = 0;
        while ( d - offset*8 > r ) {
            toB(a, ret, offset, r);
            offset += r/8;
            keccak_f(a);
        }
        toB(a, ret, offset, d - offset*8);
        return ret;
    }

    /**
     * 5.1.
     * Algorithm 9:
     * padding バイト長で計算
     */
    byte[] pad10x1() {
        int rblen = R * 8;
        int padlen = rblen - (int) ((pac.size() + 1) % rblen) + 1;
        byte[] pad = new byte[padlen];
        pad[0] |= padstart; // 種類判定用おまけbitが付く
        pad[padlen - 1] |= 0x80;
        return pad;
    }

    /**
     * SHA-512と逆
     *
     * @param src
     * @param len
     * @return
     */
    static void toB(long[] src, byte[] ret, int offset, int len) {
        int blen = (len + 7) / 8;
        int nlen = len % 8;
//        byte[] ret = new byte[blen];
        for (int i = 0; i < blen; i++) {
            ret[offset + i] = (byte) (src[i / 8] >>> ((i % 8) * 8));
        }
        if ( nlen > 0 ) { // 仮 逆かもしれない
            ret[offset + blen - 1] &= (1 << nlen) - 1;
        }
    }

    @Override
    protected byte[] engineDigest() {
        byte[] digest = sponge(d);

        engineReset();
        return digest;
    }
}
