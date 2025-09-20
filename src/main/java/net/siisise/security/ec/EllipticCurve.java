/*
 * Copyright 2024 okome.
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
 * ECDSA, EdDSA の楕円曲線

EC y^2 = add^3 + a * add + b
基準は add

EdDSA 基準は y
 */
public class EllipticCurve {

    /**
     * Curvep 内に移動するかも
     */
    public class Point {

        BigInteger x;
        BigInteger y;
        BigInteger z;

        Point(BigInteger x, BigInteger y) {
            z = BigInteger.ONE;
            this.x = x;
            this.y = y;
        }
        
        public BigInteger getX() {
            reset();
            return x;
        }
        
        public BigInteger getY() {
            reset();
            return y;
        }
        
        void reset() {
            if ( !z.equals(BigInteger.ONE)) {
                BigInteger inv = z.modInverse(p);
                x = x.multiply(inv).mod(p);
                y = y.multiply(inv).mod(p);
                z = BigInteger.ONE;
            }
        }

        boolean equals(Point b) {
            return (x.multiply(b.z).mod(p).equals(x.multiply(z).mod(p))) && (y.multiply(z).mod(p).equals(b.y.multiply(z).mod(p)));
        }
    }

    public final OBJECTIDENTIFIER oid;
    public final BigInteger p;

    /**
     * order. G から利用可能な範囲. pよりcofactor分小さいことがある powで使えるのかもしれない
     */
    public final BigInteger n;
    /**
     * cofactor
     */
    public final int h;

    public boolean equals(Object o) {
        if (o instanceof EllipticCurve) {
            EllipticCurve c = (EllipticCurve)o;
            return p.equals(c.p) && n.equals(c.n) && h == c.h;
        }
        return false;
    }
    
    /**
     * generator 
     */
    static class Curvep<P extends Curvep.Pointp> extends EllipticCurve {
        
        public class Pointp extends Point {
            Pointp(BigInteger x, BigInteger y) {
                super(x,y);
            }
        }
        /**
         * 始点
         */
        public final P G;

        Curvep(OBJECTIDENTIFIER oid, BigInteger p, BigInteger Gx, BigInteger Gy, BigInteger order, int h) {
            super(oid, p, order, h);
            G = toPoint(Gx, Gy);
        }

        Curvep(BigInteger p, BigInteger Gx, BigInteger Gy, BigInteger order, int h) {
            super(p, order, h);
            G = toPoint(Gx, Gy);
        }

        @Override
        public P toPoint(BigInteger x, BigInteger y) {
            return (P)new Pointp(x,y);
        }

        protected final BigInteger add(BigInteger a, BigInteger b) {
            return a.add(b).mod(p);
        }

        protected final BigInteger mod(BigInteger a, BigInteger b) {
            return a.mod(b);
        }

        protected final BigInteger sub(BigInteger a, BigInteger b) {
            return a.add(p).subtract(b).mod(p);
        }

        protected final BigInteger mul(BigInteger a, BigInteger b) {
            return a.multiply(b).mod(p);
        }

        protected final BigInteger pow(BigInteger a, BigInteger b) {
            return a.modPow(b, p);
        }

        protected final BigInteger pow(BigInteger a, long b) {
            return pow(a, BigInteger.valueOf(b));
        }

        protected final BigInteger div(BigInteger a, BigInteger b) {
            return a.multiply(b.modInverse(p)).mod(p);
        }
        
        public boolean equals(Object o) {
            if (o instanceof Curvep) {
                Curvep og = (Curvep)o;
                if (G.getX().equals(og.G.getX()) && G.getY().equals(og.G.getY())) {
                    super.equals(o);
                }
            }
            return false;
        }
    }

    /**
     * 仮 F2^m
     */
    static class Curvet extends EllipticCurve {
        Curvet(BigInteger p, BigInteger order, int h) {
            super(p,order,h);
        }
    }

    /**
     * 
     * @param p prime Fp
     * @param order n
     * @param h cofactor
     */
    EllipticCurve(OBJECTIDENTIFIER oid, BigInteger p, BigInteger order, int h) {
        this.oid = oid;
        this.p = p;
        n = order;
        this.h = h;
    }

    /**
     * 
     * @param p prime Fp
     * @param order n
     * @param h cofactor
     */
    EllipticCurve(BigInteger p, BigInteger order, int h) {
        oid = null;
        this.p = p;
        n = order;
        this.h = h;
    }

    /**
     * Point convert.
     * @param x 主軸?
     * @param y
     * @return 
     */
    public Point toPoint(BigInteger x, BigInteger y) {
        return new Point(x, y);
    }

    /**
     * Suite B secp.
     * RFC 6090
     * 素数をpに使う方向の楕円曲線 Fp
     * 
     * y^2 ≡ x^3 + ax + b
     */
    public static class ECCurvep<P extends ECCurvep.ECPointp> extends Curvep<P> {

        // y^2 = add^3 + ax + b
        public final BigInteger a;
        public final BigInteger b;
        public final ECPointp NULL;
        /**
         * cofactor. n * h = p ぐらい?
         */
        //public int h;

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
            BigInteger np = p.negate();
            NULL = new ECPointp(np, np);
        }

        public ECCurvep(OBJECTIDENTIFIER oid, BigInteger p, long a, BigInteger b, BigInteger Gx, BigInteger Gy, BigInteger n, int h) {
            super(oid, p, Gx, Gy, n, h);
            this.a = p.add(BigInteger.valueOf(a)).mod(p);
            this.b = p.add(b).mod(p);
            BigInteger np = p.negate();
            NULL = new ECPointp(np, np);
        }

        public ECCurvep(BigInteger p, BigInteger a, BigInteger b, BigInteger Gx, BigInteger Gy, BigInteger order, int h) {
            super(p, Gx, Gy, order, h);
            this.a = add(p, a);
            this.b = b;
            BigInteger np = p.negate();
            NULL = new ECPointp(np, np);
        }

        public ECCurvep(BigInteger p, long a, BigInteger b, BigInteger Gx, BigInteger Gy, BigInteger n, int h) {
            super(p, Gx, Gy, n, h);
            this.a = p.add(BigInteger.valueOf(a)).mod(p);
            this.b = p.add(b).mod(p);
            BigInteger np = p.negate();
            NULL = new ECPointp(np, np);
        }
        
        public class ECPointp extends Pointp {
            ECPointp(BigInteger x, BigInteger y) {
                super(x,y);
            }

            ECPointp(BigInteger x, BigInteger y, BigInteger z) {
                super(x,y);
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
            public byte[] encXY() {
                reset();
                if ( x.equals(BigInteger.ZERO) && y.equals(BigInteger.ZERO)) {
                    return new byte[] {0};
                } else {
                    PacketA d = new PacketA();
                    d.write(4);
                    d.write(encX());
                    d.write(encY());
                    return d.toByteArray();
                }
            }
            
            public byte[] encX() {
                reset();
                int qlen = (p.bitLength() + 7) / 8;
                return PKCS1.I2OSP(x, qlen);
            }

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
                if ( x.equals(BigInteger.ZERO) && y.equals(BigInteger.ZERO)) {
                    return new byte[] {0};
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
                BigInteger y2 = ECCurvep.this.add(ECCurvep.this.add(x.modPow(BigInteger.valueOf(3), p), mul(a,x)),b);
                BigInteger y = y2.sqrt();
                throw new UnsupportedOperationException();
            }

            /**
             * 加算.
             * Z考慮版.
             * @param p 点P
             * @param q 点Q
             * @return P * Q
             */
            public ECPointp add(ECPointp q) {
                if (equals(NULL)) {
                    return q;
                } else if (q.equals(NULL)) {
                    return this;
                }
                BigInteger THREE = BigInteger.valueOf(3);
                if (!equals(q)) {
                    if (x.equals(q.x)) {
                        return NULL;
                    } else {
                        BigInteger u = sub(mul(q.y,z),mul(y,q.z));
                        BigInteger u2 = pow(u,2);
                        BigInteger u3 = pow(u,3);
                        BigInteger v = sub(mul(q.x,z),mul(x, q.z));
                        BigInteger v2 = pow(v,2);
                        BigInteger v3 = pow(v,3);
                        
                        BigInteger X3 = mul(v, sub(mul(q.z,sub(mul(z,u2),mul(x.shiftLeft(1),v2))),v3));
                        BigInteger Y3 = ECCurvep.this.add(mul(q.z, sub(sub(mul(THREE.multiply(x),mul(u, v2)),mul(y,v3)),mul(z,u3))),mul(u,v3));
                        BigInteger Z3 = mul(mul(v3,z), q.z);
//                        BigInteger x3 = sub(sub(pow(div(sub(q.y, y), sub(q.x, x)), BigInteger.TWO), x), q.x);
//                        BigInteger y3 = sub(div(mul(sub(x, x3), sub(q.y, y)), sub(q.x, x)), y);
                        return new ECPointp(X3, Y3, Z3);
                    }
                }
                // x2?
                if (q.y.equals(BigInteger.ZERO)) {
                    return NULL;
                }
                BigInteger zz = pow(z,2);
                BigInteger y2 = y.shiftLeft(1);
                BigInteger yz2 = mul(y2,z);
                BigInteger w = ECCurvep.this.add(mul(THREE, pow(x,2)),mul(a,zz));
                BigInteger X3 = mul(yz2, sub(pow(w,2),mul(BigInteger.TWO.multiply(x), mul(yz2,y2))));
                BigInteger Y3 = sub(mul(pow(y2,2),mul(z, sub(mul(mul(THREE,w),x),mul(yz2,y)))), pow(w,3));
                BigInteger Z3 = pow(yz2,3);
                return new ECPointp(X3, Y3, Z3);
            }

            /**
             * 加算.
             * @param p 点P
             * @param q 点Q
             * @return P * Q
             */
/*
            public ECPointp add(ECPointp q) {
                if (equals(NULL)) {
                    return q;
                } else if (q.equals(NULL)) {
                    return this;
                }
                if (!equals(q)) {
                    if (x.equals(q.x)) {
                        return NULL;
                    } else {
                        BigInteger x3 = sub(sub(pow(div(sub(q.y, y), sub(q.x, x)), BigInteger.TWO), x), q.x);
                        BigInteger y3 = sub(div(mul(sub(x, x3), sub(q.y, y)), sub(q.x, x)), y);
                        return new ECPointp(x3, y3);
                    }
                }
                // x2?
                if (q.y.equals(BigInteger.ZERO)) {
                    return NULL;
                }
                BigInteger THREE = BigInteger.valueOf(3);
                BigInteger x3 = sub(pow(div(ECCurvep.this.add(mul(pow(x, BigInteger.TWO), THREE), ECCurvep.this.a), mul(q.y, BigInteger.TWO)), BigInteger.TWO), mul(x, BigInteger.TWO));
                BigInteger y3 = sub(div(mul(sub(x, x3), ECCurvep.this.add(mul(THREE, pow(x, BigInteger.TWO)), ECCurvep.this.a)), mul(y, BigInteger.TWO)), y);
                return new ECPointp(x3, y3);
            }
*/
            /**
             * 乗算.
             * @param n
             * @param E
             * @return 
             */
            public ECPointp x(BigInteger n) {
                ECPointp r = NULL;
                ECPointp V = this;
                int l = n.bitLength();
                for (int i = 0; i < l; i++) {
                    if (n.testBit(i)) {
                        r = r.add( V);
                    }
                    V = V.add( V); // add *= 2
                }
                return r;
            }
        }

        @Override
        public P toPoint(BigInteger x, BigInteger y) {
            return (P)new ECPointp(x,y);
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
                        return toPoint(BigInteger.ZERO,BigInteger.ZERO);
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
                    if (csize == 2*qlen) {
                        c.read(tmp);
                        BigInteger x = PKCS1.OS2IP(tmp);
                        c.read(tmp);
                        BigInteger y = PKCS1.OS2IP(tmp);
                        return toPoint(x,y);
                    }
                    break;
                default:
                    break;
            }
            throw new IllegalStateException();
        }

        public ECPointp xG(BigInteger n) {
            return G.x(n);
        }
        
        @Override
        public boolean equals(Object o) {
            if (o instanceof ECCurvep) {
                ECCurvep p = (ECCurvep)o;
                if (p.a.equals(a) && p.b.equals(b)) {
                    return super.equals(o);
                }
            }
            return false;
        }
    }

    // EC
    // NIST
    public static final ECCurvep P192;
    public static final ECCurvep P256;
    public static final ECCurvep P384;
    public static final ECCurvep P521;

    public static ECCurvep secp256k1;

    public static final ECCurvep P224;

    // EdDSA / ECDH
    public static Curve X25519;
    public static Curve X448;
    public static EdWards Ed25519;
    public static EdWards Ed448;

    static {
        
        P192 = new ECCurvep( new OBJECTIDENTIFIER("1.2.840.10045.3.1.1"),
                new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
                -3,
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
                new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
                new BigInteger("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16),
                new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
                1);
        P256 = new ECCurvep( new OBJECTIDENTIFIER("1.2.840.10045.3.1.7"),
                new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16), // p
                -3, // a
                new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16), // b
                new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16), // Gx
                new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16), // Gy
                new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16), // n
                1); // h
        P384 = new ECCurvep( new OBJECTIDENTIFIER("1.3.132.0.34"),
                new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16),
                -3,
                new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
                new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
                new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
                new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16),
                1);
        P521 = new ECCurvep( new OBJECTIDENTIFIER("1.3.132.0.35"),
                new BigInteger("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
                -3, // a
                new BigInteger("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
                new BigInteger("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
                new BigInteger("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16),
                new BigInteger("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16),
                1);

        P224 = new ECCurvep( new OBJECTIDENTIFIER("1.3.132.0.33"),
                new BigInteger("ffffffffffffffffffffffffffffffff000000000000000000000001", 16),
                -3,
                new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16),
                new BigInteger("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16),
                new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16),
                new BigInteger("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 16),
                1);

        secp256k1 = new ECCurvep( new OBJECTIDENTIFIER("1.3.132.0.10"),
                new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc2f", 16),
                BigInteger.ZERO,
                BigInteger.valueOf(7),
                new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
                new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
                new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
                1);
    }

}
