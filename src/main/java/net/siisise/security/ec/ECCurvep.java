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
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.io.PacketA;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * Suite B secp.
 * RFC 6090
 * 素数をpに使う方向の楕円曲線 Fp
 *
 * y^2 ≡ x^3 + ax + b
 */
public class ECCurvep<P extends ECCurvep.ECPointp> extends Curvep<P> implements ECCurve {

    // y^2 = add^3 + ax + b
    public final BigInteger a;
    public final BigInteger b;
    public final ECPointp NULL = new ECPointp(BigInteger.ZERO, BigInteger.ONE, BigInteger.ZERO) {
        @Override
        public ECPointp add(ECPointp a) {
            return a;
        }
    };

    /**
     * secp 系. y^2 = x^3 + ax + b 始点 G
     * 曲線の要素 p, a, b
     * generator Gx, Gy
     * 他 order, h
     *
     * @param p fieldID.parameters(prime-p) Fp prime p
     * @param a curve.a +axのa
     * @param b curve.b +bのb
     * @param Gx 始点 base.add
     * @param Gy 始点 base.y
     * @param order n order Gから利用可能な点の数
     * @param h cofactor #E(Fp)/n
     */
    public ECCurvep(OBJECTIDENTIFIER oid, BigInteger p, BigInteger a, BigInteger b, BigInteger Gx, BigInteger Gy, BigInteger order, int h) {
        super(oid, p, Gx, Gy, order, h);
        this.a = add(p, a);
        this.b = b;
    }

    public ECCurvep(OBJECTIDENTIFIER oid, BigInteger p, long a, BigInteger b, BigInteger Gx, BigInteger Gy, BigInteger n, int h) {
        this(oid, p, BigInteger.valueOf(a), b, Gx, Gy, n, h);
    }

    /**
     * 楕円曲線.
     * @param p Fp
     * @param a +ax
     * @param b +b
     * @param Gx 始点
     * @param Gy 始点
     * @param order n order Gから利用可能な点の数
     * @param h cofactor #E(Fp)/n
     */
    public ECCurvep(BigInteger p, BigInteger a, BigInteger b, BigInteger Gx, BigInteger Gy, BigInteger order, int h) {
        super(p, Gx, Gy, order, h);
        this.a = add(p, a);
        this.b = b;
    }

    public ECCurvep(BigInteger p, long a, BigInteger b, BigInteger Gx, BigInteger Gy, BigInteger n, int h) {
        this(p, BigInteger.valueOf(a), b, Gx, Gy, n, h);
    }

    public class ECPointp<P extends ECPointp> extends Pointp implements ECPoint<P> {

        ECPointp(BigInteger x, BigInteger y) {
            super(x, y);
        }

        ECPointp(BigInteger x, BigInteger y, BigInteger z) {
            super(x, y);
            this.z = z;
        }

        /**
         * 仮.
         * @param <T> 型
         * @param format 型
         * @return xyデータ
         */
        public <T> T encXY(TypeFormat<T> format) {
            reset();
            SEQUENCEMap xy = new SEQUENCEMap();
            xy.put("x", x);
            xy.put("y", y);
            return format.arrayFormat(xy);
        }

        /**
         * SEC1 2.3.3 非圧縮.
         * ゼロ 00
         * 非圧縮 04
         */
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
            reset();
            int qlen = (p.bitLength() + 7) / 8;
            return PKCS1.I2OSP(x, qlen);
        }

        @Override
        public byte[] encY() {
            reset();
            int qlen = (p.bitLength() + 7) / 8;
            return PKCS1.I2OSP(y, qlen);
        }

        /**
         * SEC1 2.3.3 圧縮.
         * ゼロ 00
         * 圧縮 02, 03
         */
        public byte[] encLXY() {
            reset();
            if (x.equals(BigInteger.ZERO) && y.equals(BigInteger.ZERO)) {
                return new byte[]{0};
            } else {
                int by = y.mod(BigInteger.TWO).intValue() + 2;
                PacketA d = new PacketA();
                d.write(by);
                int qlen = (p.bitLength() + 7) / 8;
                d.write(PKCS1.I2OSP(x, qlen));
                return d.toByteArray();
            }
        }

        BigInteger y(boolean yf, BigInteger x) {
            BigInteger y2 = add(add(x.modPow(BigInteger.valueOf(3), p), mul(a, x)), b);
            BigInteger y = y2.sqrt();
            throw new UnsupportedOperationException();
        }

        /**
         * 加算.
         *
         * Z考慮版.
         * @param p 点P
         * @param q 点Q
         * @return P * Q
         */
        @Override
        public ECPointp add(ECPointp q) {
            if (q.equals(NULL)) {
                return this;
            }
            BigInteger u = sub(mul(z, q.y), mul(y, q.z));
            BigInteger THREE = BigInteger.valueOf(3);
            if (!u.equals(BigInteger.ZERO)) {
                BigInteger v = sub(mul(q.x, z), mul(x, q.z));
                if (v.equals(BigInteger.ZERO)) {
                    return NULL;
                } else {
//                    BigInteger u = sub(mul(q.y,z),mul(y,q.z));
                    BigInteger u2 = pow(u, 2);
                    BigInteger u3 = pow(u, 3);
//                    BigInteger v = sub(mul(q.x,z),mul(x, q.z));
                    BigInteger v2 = pow(v, 2);
                    BigInteger v3 = pow(v, 3);
                    BigInteger X3 = mul(v, sub(mul(q.z, sub(mul(z, u2), mul(x.shiftLeft(1), v2))), v3));
                    BigInteger Y3 = add(mul(q.z, sub(sub(mul(THREE.multiply(x), mul(u, v2)), mul(y, v3)), mul(z, u3))), mul(u, v3));
                    BigInteger Z3 = mul(mul(v3, z), q.z);
                    return new ECPointp(X3, Y3, Z3);
                }
            }
            // x2?
            if (q.y.equals(BigInteger.ZERO)) {
                return NULL;
            }
            BigInteger zz = pow(z, 2);
            BigInteger y2 = y.shiftLeft(1);
            BigInteger yz2 = mul(y2, z);
            BigInteger w = add(mul(THREE, pow(x, 2)), mul(a, zz));
            BigInteger X3 = mul(yz2, sub(pow(w, 2), mul(BigInteger.TWO.multiply(x), mul(yz2, y2))));
            BigInteger Y3 = sub(mul(pow(y2, 2), mul(z, sub(mul(mul(THREE, w), x), mul(yz2, y)))), pow(w, 3));
            BigInteger Z3 = pow(yz2, 3);
            return new ECPointp(X3, Y3, Z3);
        }

        protected BigInteger add(BigInteger a, BigInteger... b) {
            for (BigInteger i : b) {
                a = a.add(i);
            }
            return a.mod(p);
        }

        /**
         * 乗算.
         * nG だったり nEだったり
         * @param n
         * @param E
         * @return
         */
        @Override
        public P x(BigInteger n) {
            ECPointp r = NULL;
            ECPointp V = this;
            int l = n.bitLength();
            for (int i = 0; i < l; i++) {
                if (n.testBit(i)) {
                    r = r.add(V);
                }
                V = V.add(V); // add *= 2
            }
            return (P) r;
        }
    }

    @Override
    public P toPoint(BigInteger x, BigInteger y) {
        return (P) new ECPointp(x, y);
    }

    public P toPoint(byte[] code) {
        PacketA c = new PacketA(code);
        int type = c.read();
        int csize = c.size();
        int qlen = (p.bitLength() + 7) / 8;
        byte[] tmp = new byte[qlen];
        switch (type) {
            case 0:
                if (csize == 0) {
                    return toPoint(BigInteger.ZERO, BigInteger.ZERO);
                }
                break;
            case 2:
                if (csize == qlen) {
                    c.read(tmp);
                    BigInteger x = PKCS1.OS2IP(tmp);
                    throw new UnsupportedOperationException();
                }
                break;
            case 3:
                if (csize == qlen) {
                    c.read(tmp);
                    BigInteger x = PKCS1.OS2IP(tmp);
                    throw new UnsupportedOperationException();
                }
                break;
            case 4:
                if (csize == 2 * qlen) {
                    c.read(tmp);
                    BigInteger x = PKCS1.OS2IP(tmp);
                    c.read(tmp);
                    BigInteger y = PKCS1.OS2IP(tmp);
                    return toPoint(x, y);
                }
                break;
            default:
                break;
        }
        throw new IllegalStateException();
    }

    @Override
    public P xG(BigInteger n) {
        return (P) G.x(n);
    }

    @Override
    public boolean equals(Object o) {
        if (o instanceof ECCurvep) {
            ECCurvep p = (ECCurvep) o;
            if (p.a.equals(a) && p.b.equals(b)) {
                return super.equals(o);
            }
        }
        return false;
    }
    
}
