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
package net.siisise.security.sign;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECField;
import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.util.Arrays;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.io.Output;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.ec.EllipticCurve;
import net.siisise.security.key.ECDSAPrivateKey;
import net.siisise.security.key.ECDSAPublicKey;

/**
 * ECDSA.
 * RFC 6090 楕円曲線
 * 曲線と署名用ハッシュ関数、秘密鍵または公開鍵を持つ
 */
public class ECDSA extends Output.AbstractOutput implements SignVerify {

    // RFC 8692 with SHA3
    static final OBJECTIDENTIFIER PKIX_ALGORITHMS = new OBJECTIDENTIFIER("1.3.6.1.5.5.7.6");
    public static final OBJECTIDENTIFIER ECDSA_SHAKE128 = PKIX_ALGORITHMS.sub(32);
    public static final OBJECTIDENTIFIER ECDSA_SHAKE256 = PKIX_ALGORITHMS.sub(33);

    MessageDigest md;
    ECDSAPrivateKey prv;
    ECDSAPublicKey pub;

    EllipticCurve.ECCurvep E;

    /**
     * Java ECDSA Specからの変換.
     *
     * @param spec Spec
     * @return 曲線
     */
    public static EllipticCurve.ECCurvep toCurve(ECParameterSpec spec) {
        java.security.spec.EllipticCurve c = spec.getCurve();
        ECField field = c.getField();
        if (field instanceof ECFieldFp) {
            ECFieldFp fp = (ECFieldFp) field;
            ECPoint g = spec.getGenerator();
            return new EllipticCurve.ECCurvep(fp.getP(),
                    c.getA(), c.getB(),
                    g.getAffineX(), g.getAffineY(),
                    spec.getOrder(), spec.getCofactor());
        } else {
            ECFieldF2m f2 = (ECFieldF2m) field;

            throw new UnsupportedOperationException();
        }
    }

    /**
     * Java Spec への変換.
     *
     * @param curve
     * @return
     */
    public static ECParameterSpec toSpec(EllipticCurve.ECCurvep curve) {
        ECFieldFp Fp = new ECFieldFp(curve.p);
        java.security.spec.EllipticCurve c = new java.security.spec.EllipticCurve(Fp, curve.a, curve.b);
        ECPoint g = new ECPoint(curve.G.getX(), curve.G.getY());
        return new ECParameterSpec(c, g, curve.n, curve.h);
    }

    public static ECDSAPrivateKey toECDSAKey(ECPrivateKey prv) {
        EllipticCurve.ECCurvep curve = toCurve(prv.getParams());
        BigInteger s = prv.getS();
        return new ECDSAPrivateKey(curve, s);
    }

    /**
     * Public Key の変換.
     *
     * @param pub
     * @return
     */
    public static ECDSAPublicKey toECDSAKey(ECPublicKey pub) {
        EllipticCurve.ECCurvep curve = toCurve(pub.getParams());
        ECPoint Y = pub.getW();
        return new ECDSAPublicKey(curve, Y.getAffineX(), Y.getAffineY());
    }

    /**
     *
     * @param e 楕円曲線E
     * @param h ハッシュ関数
     */
    public ECDSA(EllipticCurve.ECCurvep e, MessageDigest h) {
        this.E = e;
        md = h;
        md.reset();
    }

    /**
     * 署名用秘密鍵.
     *
     * @param prv 秘密鍵
     * @param h ハッシュ関数
     */
    public ECDSA(ECDSAPrivateKey prv, MessageDigest h) {
        this.prv = prv;
        this.E = prv.getCurve();
        this.md = h;
    }

    /**
     * 公開鍵.
     *
     * @param pub 公開鍵
     * @param h ハッシュ関数
     */
    public ECDSA(ECDSAPublicKey pub, MessageDigest h) {
        this.pub = pub;
        E = pub.getCurve();
        this.md = h;
    }

    @Override
    public int getKeyLength() {
        return (E.p.bitLength() + 7) / 8;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        md.update(src, offset, length);
    }

    BigInteger rnd() {
        int bit = prv.getCurve().p.bitLength(); // てきとうに増やす
        byte[] rnd = new byte[(bit + 9) / 8];
        try {
            SecureRandom.getInstanceStrong().nextBytes(rnd);
            rnd[0] &= 0x7f;
            return new BigInteger(rnd);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * KT-I sign 方式.
     * Rx,
     *
     * @return (s1,s2) FIPS (r,s)
     */
    @Override
    public byte[] sign() {
        byte[] h = md.digest();

        BigInteger q = E.n;
        do {
            // 0 < k < q = q = order
            BigInteger k = rnd().mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            // 2.
            try {
                return sign(h, k);
            } catch (SecurityException e) {
            }
        } while (true);
    }

    /**
     * テスト用署名乱数指定可能版.
     *
     * @param h ハッシュ済み値
     * @param k 乱数を固定
     * @return 署名
     */
    public byte[] sign(byte[] h, BigInteger k) {
        BigInteger q = E.n;

        // 2.
        // SEC.1 4.1.3. 1. kとRのペアを生成
        k = k.mod(q);
        EllipticCurve.Point R = E.xG(k);
        // 3. s1 = R_x mod q
        // SEC.1 4.1.3. 2. R_x を 変換 3. r
        BigInteger r = R.getX().mod(q);
        if (r.equals(BigInteger.ZERO)) {
            throw new SecurityException();
        }

        int blen = (E.p.bitLength() + 7) / 8;
        // 4. s2 = (h(m) + 秘密鍵z * s1)/k mod q
        // SEC.1 4.1.3 4. ハッシュ(パラメータhで済) 5. eの計算
        BigInteger e = PKCS1.OS2IP(Arrays.copyOf(h, Integer.min(h.length, blen))); // hを切り詰めた値
        BigInteger d = prv.getS();
        BigInteger s = e.add(d.multiply(r)).mod(q).multiply(k.modInverse(q)).mod(q);
        if (s.equals(BigInteger.ZERO)) {
            throw new SecurityException();
        }

        byte[] SS = new byte[blen * 2];
        byte[] S = PKCS1.I2OSP(r, blen);
        System.arraycopy(S, 0, SS, 0, blen);
        S = PKCS1.I2OSP(s, blen);
        System.arraycopy(S, 0, SS, blen, blen);
        return SS;
    }

    /**
     * KT-I verify
     *
     * @param sign (s1,s2)
     * @return 成否
     */
    @Override
    public boolean verify(byte[] sign) {
        byte[] h = md.digest();
        int blen = (E.p.bitLength() + 7) / 8;
        if (sign.length != blen * 2) {
            return false;
        }
        BigInteger q = E.n;

        byte[] S = Arrays.copyOfRange(sign, 0, blen);
        BigInteger s1 = PKCS1.OS2IP(S);
        if (s1.equals(BigInteger.ZERO) || s1.compareTo(q) >= 0) {
            return false;
        }
        S = Arrays.copyOfRange(sign, blen, blen * 2);
        BigInteger s2 = PKCS1.OS2IP(S);
        if (s2.equals(BigInteger.ZERO) || s2.compareTo(q) >= 0) {
            return false;
        }
        BigInteger s2Inv = s2.modInverse(q);

        BigInteger e = PKCS1.OS2IP(Arrays.copyOf(h, Integer.min(h.length, blen))); // hを切り詰めた値
        BigInteger u1 = e.multiply(s2Inv).mod(q);
        BigInteger u2 = s1.multiply(s2Inv).mod(q);
        EllipticCurve.ECCurvep.ECPointp Y = pub.getY();
        EllipticCurve.ECCurvep.ECPointp R = E.xG(u1).add(Y.x(u2));
        return R.getX().equals(s1);
    }
}
