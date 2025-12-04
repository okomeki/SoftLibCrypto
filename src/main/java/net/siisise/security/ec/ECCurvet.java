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
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.lang.Bin;
import net.siisise.math.GFL;

/**
 * SEC 1 2.2.2 F_2^m 上の楕円曲線
 * B系
 * y^2 + xy = x^3 + ax^2 + b
 */
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
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] encX() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        @Override
        public byte[] encY() {
            throw new UnsupportedOperationException("Not supported yet.");
        }

        /**
         * n倍
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
         * 
         * @param q
         * @return 
         */
        @Override
        public ECPointt add(ECPointt q) {
            if (q.equals(NULL)) { // 2. (x, y) + O = O + (x, y) = (x, y)
                return this;
            }
            // 3.
            //gf.
            
            BigInteger v = getX().subtract(q.getX());
            if (v.equals(BigInteger.ZERO)) {
                return getY().equals(q.getY()) ? x2() : NULL;
            }
            // 4.
            BigInteger yy = add(y, q.y);
            BigInteger xx = add(x, q.x);
            BigInteger ixx = inv(xx);
            BigInteger λ = mul(yy, ixx);
            BigInteger λ2 = pow(λ, BigInteger.TWO);
            BigInteger x3 = add(λ2,λ,x,q.x,a);
            BigInteger y3 = add(mul(λ,add(x,x3)),x3,y);
            return new ECPointt(x3,y3);
        }

        ECPointt x2() {
            // 5.
            BigInteger ix = inv(x);
            BigInteger λ = add(x, mul(y, ix));
            BigInteger λ2 = pow(λ,BigInteger.TWO);
                    
            BigInteger x3 = add(λ2,λ,a);
            BigInteger y3 = add(pow(x,BigInteger.TWO),mul(add(λ, BigInteger.ONE), x3));
            return new ECPointt(x3, y3);
        }

        BigInteger add(BigInteger a, BigInteger... b) {
            for ( BigInteger n : b ) {
                a = a.add(n);
            }
            return a.mod(p);
        }

        BigInteger mul(BigInteger a, BigInteger b) {
            return a.multiply(b).mod(p);
        }

        BigInteger pow(BigInteger a, BigInteger n) {
            return a.modPow(n, p);
        }

        BigInteger inv(BigInteger a) {
            return a.modInverse(p);
        }

    }

    public final BigInteger a;
    public final BigInteger b;
    // long[l]
    int l;
    GFL gf;
    private ECPointt G;

    /**
     *
     * @param oid OBJECTIDENTIFIER
     * @param p 素
     * @param a
     * @param b
     * @param gx
     * @param gy
     * @param order n
     * @param h
     */
    public ECCurvet(OBJECTIDENTIFIER oid, BigInteger p, int a, BigInteger b, BigInteger gx, BigInteger gy, BigInteger order, int h) {
        super(oid, p, order, h);
        this.a = BigInteger.valueOf(a);
        this.b = b;
        l = (p.bitLength() + 63) / 64;
        long[] lp = Bin.btol(Bin.toByteArray(p, l * 8));
        gf = new GFL(lp);
        G = toPoint(gx, gy);
        //g = toPoint(gx,gy);
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
