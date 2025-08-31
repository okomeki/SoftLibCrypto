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
package net.siisise.security.key;

import java.math.BigInteger;
import java.util.Arrays;
import net.siisise.lang.Bin;
import net.siisise.security.ec.GF;

/**
 * 謎のモンゴメリー曲線. RFC 7748
 */
public class ECDH {

    static abstract class Curve {

        final BigInteger p;
        final BigInteger a;
        final BigInteger a24;
//        final BigInteger l;
//        int c;
        int b;
        public final byte[] u;
        final int c;
//        BigInteger v;

        Curve(BigInteger p, int b, BigInteger a, BigInteger l, int c, BigInteger u) {
            this.p = p;
            this.b = b;
            this.a = a;
            this.u = u.toByteArray();
            a24 = a.subtract(BigInteger.TWO).shiftRight(2);
            this.c = c;
        }

        /**
         * v^2 = u^3 + A*u^2 + u
         *
         * @param su
         * @return
         */
        BigInteger v(BigInteger su) {
            GF u = new GF(p).val(su);
            GF A = u.val(a);
            GF vv = u.pow(3).add(A.mul(u.pow(2))).add(u);
            throw new IllegalStateException();
        }

        /**
         * k の
         *
         * @param sc
         * @return
         */
        public byte[] cutk(byte[] sc) {
            byte[] s = sc.clone();
            s[0] &= 0xff << c;
            int n = b - 1; // 最上位フラグ位置
            int tn = n / 8;
            for (int i = tn + 1; i < s.length; i++) {
                s[i] = 0;
            }
            s[tn] &= 0xff >>> (7 - (n % 8));
            s[tn] |= 1 << (n % 8);
            return s;
        }

        public byte[] toB(BigInteger i) {
            byte[] bi = i.toByteArray();
            bi = Arrays.copyOfRange(bi, bi.length - (b + 1) / 8, bi.length);
            return Bin.rev(bi);
        }

        public byte[] x(byte[] k, byte[] u) {
            BigInteger ik = Bin.lbtobi(k); //cuts(k);
            byte[] uc = u.clone();
            //uc[uc.length - 1] &= 0x7f; // 互換 X25519のみ
            BigInteger iu = Bin.lbtobi(uc);
            BigInteger ia = x(ik, iu);
            return toB(ia);
        }

        /**
         *
         * @param k 秘密鍵 スカラー
         * @param u Curve25519 9 Curve448 5 または相手の公開鍵
         * @return 公開鍵または共通鍵
         */
        public BigInteger x(BigInteger k, BigInteger u) {
            u = u.clearBit(b).mod(p);

            GF x_1 = new GF(u, p);
            GF x_2 = x_1.val(BigInteger.ONE);
            GF z_2 = x_1.val(BigInteger.ZERO);
            GF x_3 = x_1.val(u);
            GF z_3 = x_1.val(BigInteger.ONE);
            BigInteger swap = BigInteger.ZERO;

            for (int t = b - 1; t >= 0; t--) {
                boolean k_t = k.testBit(t);
                if (k_t) {
                    swap = swap.flipBit(0);
                }
                // 条件付きswap
                BigInteger[] sw = cswap(swap, x_2.val, x_3.val);
                x_2 = x_2.val(sw[0]);
                x_3 = x_3.val(sw[1]);
                sw = cswap(swap, z_2.val, z_3.val);
                z_2 = z_2.val(sw[0]);
                z_3 = z_3.val(sw[1]);
                swap = k_t ? BigInteger.ONE : BigInteger.ZERO;

                GF A = x_2.add(z_2);
                GF AA = A.pow(BigInteger.TWO);
                GF B = x_2.sub(z_2);
                GF BB = B.pow(BigInteger.TWO);
                GF E = AA.sub(BB);
                GF C = x_3.add(z_3);
                GF D = x_3.sub(z_3);
                GF DA = D.mul(A);
                GF CB = C.mul(B);
                x_3 = DA.add(CB).pow(BigInteger.TWO);
                z_3 = x_1.mul(DA.sub(CB).pow(BigInteger.TWO));
                x_2 = AA.mul(BB);
                z_2 = E.mul(AA.add(E.mul(a24)));
            }
            BigInteger[] sw = cswap(swap, x_2.val, x_3.val);
            x_2 = x_2.val(sw[0]);
            //x_3 = new GF(sw[1],p);
            sw = cswap(swap, z_2.val, z_3.val);
            z_2 = z_2.val(sw[0]);
            //z_3 = new GF(sw[1],p);
            return x_2.mul(z_2.pow(p.subtract(BigInteger.TWO))).val;
        }

        BigInteger[] cswap(BigInteger swap, BigInteger a, BigInteger b) {
            BigInteger mask = swap.negate();
            BigInteger dummy = mask.and(a.xor(b));
            BigInteger[] ab = new BigInteger[2];
            ab[0] = a.xor(dummy);
            ab[1] = b.xor(dummy);
            return ab;
        }
    }

    static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger A25519 = BigInteger.valueOf(486662);
    static final BigInteger L25519 = BigInteger.ONE.shiftLeft(252).add(new BigInteger("14def9dea2f79cd65812631a5cf5d3ed", 16));
    static final BigInteger U25519 = BigInteger.valueOf(9);

    static final BigInteger P448 = BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224).add(BigInteger.ONE));
    static final BigInteger A448 = BigInteger.valueOf(156326);
    static final BigInteger L448 = BigInteger.ONE.shiftLeft(446).subtract(new BigInteger("8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d", 16));
    static final BigInteger U448 = BigInteger.valueOf(5);

    public static class Curve25519 extends Curve {

        public Curve25519() {
            super(P25519, 255, A25519, L25519, 3, U25519);
        }
    }

    public static class Curve448 extends Curve {

        public Curve448() {
            super(P448, 448, A448, L448, 2, U448);
        }
    }

}
