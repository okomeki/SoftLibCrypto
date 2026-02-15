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

import net.siisise.security.math.BIGF;
import java.math.BigInteger;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.io.PacketA;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;

/**
 * SEC 1 2.2.2 F_2^m 上のバイナリな楕円曲線
 * B系
 * y^2 + xy = x^3 + ax^2 + b
 *
 * @param <P>
 * @deprecated まだ
 */
@Deprecated
public class ECCurvet<P extends ECCurvet.ECPointt> extends Curvet<P> implements ECCurve {

    public final ECPointt NULL = new ECPointt(BigInteger.ZERO, BigInteger.ONE) {
        @Override
        /**
         * 1. O + O = O
         * 2. (x,y) + O = O + (x, y) = (x, y)
         */
        public ECPointt add(ECPointt a) {
            return a;
        }
    };

    public class ECPointt extends Pointt implements ECPoint<ECPointt> {

        public ECPointt(BigInteger x, BigInteger y) {
            super(x, y);
        }

        @Override
        public byte[] encXY() {
            reset();
            if (x.equals(BigInteger.ZERO) && y.equals(BigInteger.ZERO)) {
                return new byte[]{0};
            } else {
                PacketA d = new PacketA();
                d.write(4);
                d.write(encX());
                d.write(encY());
                return d.toByteArray();
            }
        }

        @Override
        public byte[] encX() {
            int qlen = (p.bitLength() + 7) / 8;
            return PKCS1.I2OSP(x, qlen);
        }

        @Override
        public byte[] encY() {
            int qlen = (p.bitLength() + 7) / 8;
            return PKCS1.I2OSP(y, qlen);
        }

        /**
         * n倍
         *
         * @param n
         * @return
         */
        @Override
        public P x(BigInteger n) {
            ECPointt r = NULL;
            ECPointt V = this;
            int l = n.bitLength();
            for (int i = 0; i < l; i++) {
                if (n.testBit(i)) {
                    r = r.add(V);
                }
                V = V.x2(); // add *= 2
            }
            return (P) r;
        }

        /**
         * SEC 1 2.2.2. F_2^m 上の楕円曲線 加法規則
         * SP 800-186 A.2.
         *
         * @param q
         * @return
         */
        @Override
        public ECPointt add(ECPointt q) {
            // 1. 2.
            if (q.equals(NULL)) { // 2. (x, y) + O = O + (x, y) = (x, y)
                return this;
            }
            // 3.
            if (getX().equals(q.getX())) {
                // 5.
                return getY().equals(q.getY()) ? x2() : NULL;
            }
            // 4. 2点が異なる場合
            // x3 = λ^2 + λ + x_1 + x_2 + a
            // y3 = λ(x1 + x3) + x3 + y1
            BigInteger yy = gf.add(y, q.y);
            BigInteger xx = gf.add(x, q.x);
            BigInteger ixx = gf.inv(xx);
            BigInteger λ = gf.mul(yy, ixx); // GF_2^m
            BigInteger λ2 = gf.mul(λ,λ);
            BigInteger x3 = gf.add(λ2, λ, x, q.x, a);
            
            BigInteger y3 = gf.add(gf.mul(λ, gf.add(x, x3)), x3, y);
            return new ECPointt(x3, y3);
        }
        
        /**
         * 2倍? 2乗?
         *
         * @return
         */
        ECPointt x2() {
            // 5.
            BigInteger λ = gf.add(x, gf.mul(y, gf.inv(x)));
            BigInteger λ2 = gf.mul(λ,λ);

            BigInteger xx = gf.mul(x, x);
            BigInteger x3 = gf.add(λ2, λ, a);
            BigInteger y3 = gf.add(xx, gf.mul(gf.add(λ, BigInteger.ONE), x3));
            
            return new ECPointt(x3, y3);
        }
    }

    int T;
    public final BigInteger a;
    public final BigInteger b;
    // long[l]
//    int l;
    BIGF gf;
    private ECPointt G;

    /**
     * ランダム曲線 h = 2 Koblitz曲線 a = 1 の場合は h = 2 a = 0 の場合は h = 4
     *
     * @param oid OBJECTIDENTIFIER
     * @param p 多項式 f(z) 有限体のサイズ
     * @param a coefficient a 係数
     * @param b coefficient b
     * @param gx generator x 生成元
     * @param gy generator y 生成元
     * @param n order 位数
     * @param h cofactor &lt;= 4
     */
    public ECCurvet(OBJECTIDENTIFIER oid, BigInteger p, int a, BigInteger b, BigInteger gx, BigInteger gy, BigInteger n, int h) {
        super(oid, p, n, h);
        this.a = BigInteger.valueOf(a);
        this.b = b;
//        l = (p.bitLength() + 63) / 64;
        gf = new BIGF(p);
        G = toPoint(gx, gy);
    }

    @Override
    public P toPoint(BigInteger x, BigInteger y) {
        return (P) new ECPointt(x, y);
    }

    @Override
    public ECPointt getG() {
        return G;
    }

    @Override
    public ECPointt xG(BigInteger n) {
        return G.x(n);
    }

}
