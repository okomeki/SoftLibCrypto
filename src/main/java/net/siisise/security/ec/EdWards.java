/*
 * Copyright 2025 okome.
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
package net.siisise.security.ec;

import java.math.BigInteger;
import net.siisise.io.PacketA;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.lang.Bin;
import net.siisise.security.digest.BlockMessageDigest;

/**
 * EdWards曲線.
 * RFC 8032 3.のパラメータ.
 */
public abstract class EdWards {

    public final OBJECTIDENTIFIER oid;
    // 1. GF(p) 奇数
    final BigInteger p;
    // 2. 鍵と署名のサイズの元 2^(b-1) > p
    public final int b;
    // 5. 対数 c 2または3
    // c <= n < b 上位ビットから有効なビット数
    public final int c;
    // 6. c <= n < b
    public final int n;
    // 7. GF(p)の非正方形要素
    final BigInteger d;
    // 8. GF(p)の非ゼロの正方形要素
    private final BigInteger a;
    // 9. B
    public final Point B;
    final Point ZP;
    // 10. 素数
    public final BigInteger L;
    // 11. prehash
    //        MessageDigest PH;
    private final byte[] SIG;
    /**
     * 空dom
     */
    final byte[] ID;

    /**
     * 
     * @param oid
     * @param p p
     * @param b
     * @param c
     * @param n n?
     * @param a
     * @param d
     * @param Bx Gx
     * @param By Gy
     * @param L n
     * @param SIG
     * @param IC 
     */
    EdWards(OBJECTIDENTIFIER oid, BigInteger p, int b, int c, int n, int a, BigInteger d, BigInteger Bx, BigInteger By, BigInteger L, byte[] SIG, byte[] IC) {
        this.oid = oid;
        this.p = p;
        this.b = b;
        this.c = c;
        this.n = n;
        this.a = BigInteger.valueOf(a);
        this.d = d;
        //            this.B = decXY(itob(By,b));
        this.B = toPoint(Bx, By);
        this.ZP = toPoint(BigInteger.ZERO, BigInteger.ONE);
        this.L = L;
        this.SIG = SIG;
        this.ID = dom(0, IC);
    } //            this.B = decXY(itob(By,b));

    /**
     * ハッシュの頭.
     *
     * @param x
     * @param y dom
     * @return
     */
    public final byte[] dom(int x, byte[] y) {
        PacketA dom = new PacketA();
        if (y != null) {
            dom.write(SIG);
            dom.write((byte) x);
            dom.write((byte) y.length); // 32bit int
            dom.write(y);
        }
        return dom.toByteArray();
    }

    /**
     * 空dom
     * @return 空dom
     */
    public byte[] id() {
        return ID;
    }

    public abstract BlockMessageDigest H();

    /*
     * PH ぷりハッシュ計算.
     *
     * @param x message
     * @return hash
     */
    public byte[] PH(byte[] x) {
        return x;
    }

    public BigInteger cuts(byte[] s) {
        s[0] &= 0xff << c;
        s = Bin.rev(s);
        int n = s.length - this.n / 8 - 1;
        for (int i = 0; i < n; i++) {
            s[i] = 0;
        }
        s[n] &= 0xff >>> (7 - (this.n % 8));
        s[n] |= 1 << (this.n % 8);
        return new BigInteger(s);
    }

    /**
     * s mod L  の符号化.
     *
     * @param s
     * @return s mod L の符号化
     */
    public byte[] ENC(BigInteger s) {
        return Bin.bitolb(s.mod(L), b / 8);
    }
    
    BigInteger add(BigInteger a, BigInteger b) {
        return a.add(b).mod(p);
    }

    BigInteger addP(BigInteger a, BigInteger b) {
        return a.add(b).mod(p);
    }
    
    BigInteger sub(BigInteger a, BigInteger b) {
        return p.add(a).subtract(b).mod(p);
    }
    
    BigInteger mul(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(p);
    }
    
    BigInteger pow(BigInteger a, BigInteger b) {
        return a.modPow(b, p);
    }

    public abstract class Point {

        protected BigInteger X;
        protected BigInteger Y;
        protected BigInteger Z;

        void reset() {
            if (!Z.equals(BigInteger.ONE)) {
                BigInteger r = Z.modInverse(p);
                Z = BigInteger.ONE;
                X = mul(X, r);
                Y = mul(Y, r);
            }
        }

        public boolean equals(Point p) {
            //                reset();
            //                p.reset();
            return sub(mul(X, p.Z), mul(p.X, Z)).equals(BigInteger.ZERO) && sub(mul(Y,p.Z), mul(p.Y,Z)).equals(BigInteger.ZERO);
        }

        /**
         * 5.1.2. Encoding.
         *
         * @return
         */
        public byte[] encXY() {
            reset();
            byte[] code = Bin.bitolb(Y, b / 8);
            code[code.length - 1] |= X.testBit(0) ? 0x80 : 0;
            return code;
        }

        /**
         * 加算.
         * @param x
         * @return 
         */
        public abstract Point add(Point x);

        abstract Point x2();

        /**
         * 乗算.
         * @param x
         * @return 
         */
        public Point nE(BigInteger x) {
            Point r = ZP;
            Point p = this;
            int bl = x.bitLength();
            for (int i = 0; i < bl; i++) {
                if (x.testBit(i)) {
                    r = r.add(p);
                }
                p = p.x2();
            }
            return r;
        }
    }

    /**
     * 5.1.3. Decoding.
     * 5.2.3.
     *
     * @param code 5.1.2で符号化されたもの
     * @return 復元Point
     */
    public Point decXY(byte[] code) {
        // 1. xフラグとy座標の分離
        byte[] by = Bin.rev(code);
        boolean x_0 = (by[0] & 0x80) != 0;
        by[0] &= 0x7f;
        BigInteger y = new BigInteger(by);
        if (y.compareTo(p) >= 0) {
            throw new IllegalStateException();
        }
        // 2.
        // EdWards25519 x^2 = (y^2 - 1)(dy^2 + 1)
        // EdWards448   x^2 = (y^2 - 1)(dy^2 - 1)
        BigInteger yy = pow(y, BigInteger.TWO);
        BigInteger u = sub(yy, BigInteger.ONE);
        BigInteger v = sub(mul(yy, d), a);
        BigInteger uv = mul(u, v);
        BigInteger x = mul(u, uv.modPow(p.shiftRight(c),p));
        // 3.
        BigInteger vxx = mul(v, pow(x,BigInteger.TWO));
        x = xCheck(x, vxx, u);
        // 4.
        if (x_0 && x.equals(BigInteger.ZERO)) {
            throw new IllegalStateException();
        }
        if (x.testBit(0) != x_0) {
            x = x.negate();
        }
        return toPoint(x, y);
    }

    abstract BigInteger xCheck(BigInteger x, BigInteger vxx, BigInteger u);

    abstract Point toPoint(BigInteger x, BigInteger y);

    public byte[] nE(BigInteger x) {
        return B.nE(x).encXY();
    }
    
}
