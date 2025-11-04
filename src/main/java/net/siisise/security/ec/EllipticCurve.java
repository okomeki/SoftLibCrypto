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
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;

/**
 * ECDSA, EdDSA の楕円曲線
 *
 * EC y^2 = add^3 + a * add + b
 * 基準は add
 *
 * EdDSA 基準は y
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
            if (!z.equals(BigInteger.ONE)) {
                BigInteger inv = z.modInverse(p);
                x = x.multiply(inv).mod(p);
                y = y.multiply(inv).mod(p);
                z = BigInteger.ONE;
            }
        }

        boolean equals(Point b) {
            return (x.multiply(b.z).mod(p).equals(x.multiply(z).mod(p))) && (y.multiply(z).mod(p).equals(b.y.multiply(z).mod(p)));
        }

        public Point x(BigInteger n) {
            throw new IllegalStateException();
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
            EllipticCurve c = (EllipticCurve) o;
            return p.equals(c.p) && n.equals(c.n) && h == c.h;
        }
        return false;
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

    public OBJECTIDENTIFIER getOID() {
        return oid;
    }

    public BigInteger getP() {
        return p;
    }

    public BigInteger getN() {
        return n;
    }

    /**
     * Point convert.
     *
     * @param x 主軸?
     * @param y
     * @return
     */
    public Point toPoint(BigInteger x, BigInteger y) {
        return new Point(x, y);
    }

    public interface ECPoint<P extends ECPoint> {

        byte[] encXY();
        byte[] encX();
        byte[] encY();
        BigInteger getX();
        BigInteger getY();
        P x(BigInteger n);
        P add(P a);
    }

    public ECPoint xG(BigInteger p) {
        throw new IllegalStateException();
    }

    // EC
    // NIST
    @Deprecated
    public static final ECCurvep P192; // 廃止
    public static final ECCurvep P224;
    public static final ECCurvep P256;
    public static final ECCurvep P384;
    public static final ECCurvep P521;

    public static ECCurvep secp256k1;

    @Deprecated
    public static final ECCurvet B283;
    @Deprecated
    public static final ECCurvet B409;

    // EdDSA / ECDH
    public static Curve X25519;
    public static Curve X448;
    public static EdWards Ed25519;
    public static EdWards Ed448;

    static {

        P192 = new ECCurvep(new OBJECTIDENTIFIER("1.2.840.10045.3.1.1"),
                new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
                -3,
                new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
                new BigInteger("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
                new BigInteger("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16),
                new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
                1);
        P256 = new ECCurvep(new OBJECTIDENTIFIER("1.2.840.10045.3.1.7"),
                new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16), // p
                -3, // a
                new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16), // b
                new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16), // Gx
                new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16), // Gy
                new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16), // n
                1); // h
        secp256k1 = new ECCurvep(new OBJECTIDENTIFIER("1.3.132.0.10"),
                new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc2f", 16),
                BigInteger.ZERO,
                BigInteger.valueOf(7),
                new BigInteger("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", 16),
                new BigInteger("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
                new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
                1);
        B283 = new ECCurvet(new OBJECTIDENTIFIER("1.3.132.0.17"),
                BigInteger.ONE.shiftLeft(283).add(BigInteger.valueOf(4096 + 128 + 32 + 1)),
                1,
                new BigInteger("027b680ac8b8596da5a4af8a19a0303fca97fd7645309fa2a581485af6263e313b79a2f5", 16),
                new BigInteger("05f939258db7dd90e1934f8c70b0dfec2eed25b8557eac9c80e2e198f8cdbecd86b12053", 16),
                new BigInteger("03676854fe24141cb98fe6d4b20d02b4516ff702350eddb0826779c813f0df45be8112f4", 16),
                new BigInteger("03ffffffffffffffffffffffffffffffffffef90399660fc938a90165b042a7cefadb307", 16),
                2);
        P224 = new ECCurvep(new OBJECTIDENTIFIER("1.3.132.0.33"),
                new BigInteger("ffffffffffffffffffffffffffffffff000000000000000000000001", 16),
                -3,
                new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16),
                new BigInteger("b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21", 16),
                new BigInteger("bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16),
                new BigInteger("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 16),
                1);
        P384 = new ECCurvep(new OBJECTIDENTIFIER("1.3.132.0.34"),
                new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16),
                -3,
                new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
                new BigInteger("aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7", 16),
                new BigInteger("3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
                new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16),
                1);
        P521 = new ECCurvep(new OBJECTIDENTIFIER("1.3.132.0.35"),
                new BigInteger("01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
                -3, // a
                new BigInteger("0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
                new BigInteger("00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66", 16),
                new BigInteger("011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16),
                new BigInteger("01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16),
                1);
        B409 = new ECCurvet(new OBJECTIDENTIFIER("1.3.132.0.37"),
                BigInteger.ONE.shiftLeft(409).add(BigInteger.ONE.shiftLeft(87)).add(BigInteger.ONE),
                1,
                new BigInteger("0021a5c2c8ee9feb5c4b9a753b7b476b7fd6422ef1f3dd674761fa99d6ac27c8a9a197b272822f6cd57a55aa4f50ae317b13545f", 16),
                new BigInteger("015d4860d088ddb3496b0c6064756260441cde4af1771d4db01ffe5b34e59703dc255a868a1180515603aeab60794e54bb7996a7", 16),
                new BigInteger("0061b1cfab6be5f32bbfa78324ed106a7636b9c5a7bd198d0158aa4f5488d08f38514f1fdf4b4f40d2181b3681c364ba0273c706", 16),
                new BigInteger("010000000000000000000000000000000000000000000000000001e2aad6a612f33307be5fa47c3c9e052f838164cd37d9a21173", 16),
                2);
    }

}
