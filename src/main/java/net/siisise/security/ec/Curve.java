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
import net.siisise.lang.Bin;

/**
 * RFC 7748 ECDH モンゴメリ曲線.
 * Curve25519 Curve448
 * v^2 = u^3 + Au^2 + u
 */
public abstract class Curve extends EllipticCurve.Curvep {

    static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger L25519 = BigInteger.ONE.shiftLeft(252).add(new BigInteger("14def9dea2f79cd65812631a5cf5d3ed", 16));

    static final BigInteger P448 = BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224).add(BigInteger.ONE));
    static final BigInteger L448 = BigInteger.ONE.shiftLeft(446).subtract(new BigInteger("8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d", 16));

    public final String name;
    /**
     * bit length
     */
    public final int b;
    public final BigInteger a;
    protected final BigInteger a24;
    protected final int c;
    public byte[] Pu;

    /**
     *
     * @param p P Fp
     * @param A A
     * @param n order
     * @param c 2^c = cofactor
     * @param u Pのuのみ
     */
    protected Curve(String name, BigInteger p, int A, BigInteger n, int c, int u) {
        super(p, BigInteger.valueOf(u), BigInteger.ZERO, n, 1 << c);
        this.name = name;
        this.b = p.bitLength();
        this.a = BigInteger.valueOf(A);
        this.c = c;
        a24 = this.a.subtract(BigInteger.TWO).shiftRight(2);
        this.Pu = BigInteger.valueOf(u).toByteArray();
    }

    /**
     * 仮に v を出してみる.
     * v^2 = u^3 + A*u^2 + u フラグは参考程度.
     * 5.1.1. x = a^((p+3)/8) ( mod p) x = u(uv)^(p - 5)/8 ( mod p)
     * 5.2.1. x = a^((p+1)/4) ( mod p) x = u(uv)^(p - 3)/4 ( mod p)
     *
     * @param bu 符号化されたuvっぽいもの
     * @return v v座標っぽいもの
     */
    public BigInteger v(byte[] bu) {
        boolean u_0 = (bu[bu.length - 1] & 0x80) != 0;
        byte[] cu = clearFlag(bu);
        BigInteger u = Bin.lbtobi(cu).mod(p);
        return v(u_0, u);
    }

    BigInteger v(boolean u_0, BigInteger u) {
        BigInteger vv = mul(u, add(mul(u, add(u, a)), BigInteger.ONE));
        BigInteger v = pow(vv, p.shiftRight(c).add(BigInteger.ONE));
        v = vCheck(v, vv);
        if (u_0 && BigInteger.ZERO.equals(v)) {
            throw new IllegalStateException();
        }
        if (u_0 != v.testBit(0)) {
            // 適当な仮
            v = p.subtract(v);
        }
        return v;
    }

    /**
     * フラグビットクリア.
     * X448 はフラグビットの余裕がないので参照するだけ.
     *
     * @param bu UV
     * @return U
     */
    abstract protected byte[] clearFlag(byte[] bu);

    /**
     * 符号混合デコード.
     * @param u 符号付きとみなし
     * @return (u,v)
     */
    public Point v(BigInteger u) {
        return new Point( u, v(Bin.bitolb(u, (b + 1) / 8)));
    }

    abstract BigInteger vCheck(BigInteger v, BigInteger a);

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

    /**
     * kPの計算.
     * u は Pの座標
     *
     * @param k 数
     * @param u Pointのuのみ
     * @return 新しいu
     */
    public byte[] x(byte[] k, byte[] u) {
        BigInteger ik = Bin.lbtobi(k); //cuts(k);
        //uc[uc.length - 1] &= 0x7f; // 互換 X25519のみ
        BigInteger iu = Bin.lbtobi(u);
        BigInteger ia = x(ik, iu);
        return Bin.bitolb(ia, (b + 1) / 8);
    }

    /**
     * kPの計算.
     * u は Pの座標.
     *
     * @param k 数
     * @param u Curve25519 9 Curve448 5 または相手の公開鍵
     * @return 公開鍵または共通鍵
     */
    public BigInteger x(BigInteger k, BigInteger u) {
        u = u.clearBit(b).mod(p);
        BigInteger x_1 = u;
        BigInteger x_2 = BigInteger.ONE;
        BigInteger z_2 = BigInteger.ZERO;
        BigInteger x_3 = u;
        BigInteger z_3 = x_2;
        boolean swap = false;
        for (int t = b - 1; t >= 0; t--) {
            boolean k_t = k.testBit(t);
            swap = swap ^ k_t;
            // 条件付きswap
            BigInteger[] sw = cswap(swap, x_2, x_3);
            x_2 = sw[0];
            x_3 = sw[1];
            sw = cswap(swap, z_2, z_3);
            z_2 = sw[0];
            z_3 = sw[1];
            swap = k_t;
            BigInteger A = add(x_2, z_2);
            BigInteger AA = pow(A, BigInteger.TWO);
            BigInteger B = sub(x_2, z_2);
            BigInteger BB = pow(B, BigInteger.TWO);
            BigInteger E = sub(AA, BB);
            BigInteger C = add(x_3, z_3);
            BigInteger D = sub(x_3, z_3);
            BigInteger DA = mul(D, A);
            BigInteger CB = mul(C, B);
            x_3 = pow(add(DA, CB), BigInteger.TWO);
            z_3 = mul(x_1, pow(sub(DA, CB), BigInteger.TWO));
            x_2 = mul(AA, BB);
            z_2 = mul(E, add(AA, mul(E, a24)));
        }
        BigInteger[] sw = cswap(swap, x_2, x_3);
        x_2 = sw[0];
        //x_3 = new Modular(sw[1],p);
        sw = cswap(swap, z_2, z_3);
        z_2 = sw[0];
        //z_3 = new Modular(sw[1],p);
        return mul(x_2, pow(z_2, p.subtract(BigInteger.TWO)));
    }

    private BigInteger[] cswap(boolean swap, BigInteger a, BigInteger b) {
        BigInteger mask = BigInteger.valueOf(swap ? -1l : 0l);
        BigInteger dummy = mask.and(a.xor(b));
        BigInteger[] ab = new BigInteger[2];
        ab[0] = a.xor(dummy);
        ab[1] = b.xor(dummy);
        return ab;
    }

}
