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
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.io.Output;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.security.ec.ECCurve;
import net.siisise.security.ec.ECCurvep;
import net.siisise.security.ec.ECCurvet;
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

    ECCurve E;

    final MessageDigest md;
    /**
     * 署名用秘密鍵.
     */
    ECDSAPrivateKey prv;
    /**
     * 検証用公開鍵.
     */
    ECDSAPublicKey pub;

    /**
     * Java ECDSA Specからの変換.
     *
     * @param spec Spec
     * @return 曲線
     */
    public static ECCurve toCurve(ECParameterSpec spec) {
        java.security.spec.EllipticCurve c = spec.getCurve();
        ECField field = c.getField();
        ECPoint g = spec.getGenerator();
        if (field instanceof ECFieldFp) {
            ECFieldFp fp = (ECFieldFp) field;
            return new ECCurvep(fp.getP(),
                    c.getA(), c.getB(),
                    g.getAffineX(), g.getAffineY(),
                    spec.getOrder(), spec.getCofactor());
        } else if (field instanceof ECFieldF2m) {
            ECFieldF2m f2m = (ECFieldF2m) field;
            g = spec.getGenerator();
            return new ECCurvet(f2m.getReductionPolynomial(),
                    c.getA(), c.getB(),
                    g.getAffineX(), g.getAffineY(),
                    spec.getOrder(), spec.getCofactor());
        } else {
            throw new UnsupportedOperationException();
        }
    }

    /**
     * Java Spec への変換.
     * pとtあとでまとめる?
     *
     * @param curve
     * @return
     */
    public static ECParameterSpec toSpec(ECCurvep curve) {
        ECFieldFp Fp = new ECFieldFp(curve.p);
        java.security.spec.EllipticCurve c = new java.security.spec.EllipticCurve(Fp, curve.a, curve.b);
        ECPoint g = new ECPoint(curve.G.getX(), curve.G.getY());
        return new ECParameterSpec(c, g, curve.n, curve.h);
    }

    public static ECParameterSpec toSpec(ECCurvet curve) {
        ECFieldF2m F2m = new ECFieldF2m(curve.p.bitLength(), curve.p);
        java.security.spec.EllipticCurve c = new java.security.spec.EllipticCurve(F2m, curve.a, curve.b);
        ECPoint g = new ECPoint(curve.getG().getX(), curve.getG().getY());
        return new ECParameterSpec(c, g, curve.n, curve.h);
    }

    public static ECParameterSpec toSpec(ECCurve curve) {
        if (curve instanceof ECCurvep) {
            return toSpec((ECCurvep) curve);
        } else if (curve instanceof ECCurvet) {
            return toSpec((ECCurvet) curve);
        }
        throw new IllegalStateException();
    }

    public static ECDSAPrivateKey toECDSAKey(ECPrivateKey prv) {
        ECCurve curve = toCurve(prv.getParams());
        BigInteger s = prv.getS();
        return new ECDSAPrivateKey(curve, s);
    }

    /**
     * Public Key の変換.
     *
     * @param pub Java形式公開鍵
     * @return SoftLib 公開鍵
     */
    public static ECDSAPublicKey toECDSAKey(ECPublicKey pub) {
        ECCurve curve = toCurve(pub.getParams());
        ECPoint Y = pub.getW();
        return new ECDSAPublicKey(curve, Y.getAffineX(), Y.getAffineY());
    }

    /**
     * ECDSA署名初期設定.
     * 出力はP1363形式 (仮)
     * @param h ハッシュ関数
     */
    protected ECDSA(MessageDigest h) {
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
        this(h);
        init(prv);
    }

    /**
     * 検証用公開鍵.
     *
     * @param pub 公開鍵
     * @param h ハッシュ関数
     */
    public ECDSA(ECDSAPublicKey pub, MessageDigest h) {
        this(h);
        init(pub);
    }

    public void init(ECDSAPublicKey pub) {
        this.pub = pub;
        E = pub.getCurve();
        md.reset();
    }

    public void init(ECDSAPrivateKey prv) {
        this.prv = prv;
        E = prv.getCurve();
        md.reset();
    }

    @Override
    public int getKeyLength() {
        return (E.getP().bitLength() + 7) / 8;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        md.update(src, offset, length);
    }

    /**
     * KT-I sign 方式.
     * Rx,
     *
     * @return (s1,s2) FIPS (r,s)
     */
    @Override
    public byte[] sign() {
        return sign(new P1363Format(E.getP().bitLength()));
    }
    
    public <T> T sign(TypeFormat<T> format) {
        byte[] h = md.digest();

        do {
            // 0 < k < q = q = order 乱数生成
            BigInteger k = genK(h);
            // 2.
            try {
                return sign(h, k, format);
            } catch (SecurityException e) {
            }
        } while (true);
    }
    
    public byte[] sign(ECDSAPrivateKey prv) {
        this.prv = prv;
        E = prv.getCurve();
        return sign();
    }

    private SecureRandom rnd;

    /**
     * 乱数っぽいものの生成.
     * 重複しないこと
     *
     * @param h ハッシュ値 決定論的ECDSAで使用、ECDSAでは不要
     * @return 0 &lt; k &lt; q
     */
    BigInteger genK(byte[] h) {
        BigInteger q = E.getN();
        int len = (q.bitLength() + 8) / 8;
        byte[] bytes = new byte[len];
        try {
            if (rnd == null) {
                rnd = SecureRandom.getInstanceStrong();
            }
            rnd.nextBytes(bytes);
            bytes[0] &= 0x7f;
            return new BigInteger(bytes).mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    public byte[] sign(byte[] h, BigInteger k) {
        return sign(h, k, new P1363Format(E.getP().bitLength()));
    }

    /**
     * KT-I署名.
     * テスト用署名乱数指定可能版.
     *
     * @param <T>
     * @param h ハッシュ済み値
     * @param k 乱数を固定 1 から order -1
     * @param format
     * @return 署名
     */
    public <T> T sign(byte[] h, BigInteger k, TypeFormat<T> format) {
        BigInteger q = E.getN(); // order

        // SEC.1 4.1.3. 1. kとRのペアを生成
        // RFC 6090 1. 1 から q-1までの間
        k = k.mod(q); // 念の為
        // 2. R = (r_x, r_y) = alpha^k
        EllipticCurve.ECPoint R = E.xG(k);
        // 3. s1 = R_x mod q
        // SEC.1 4.1.3. 2. R_x を 変換 3. r
        BigInteger s1 = R.getX().mod(q);
        if (s1.equals(BigInteger.ZERO)) {
            throw new SecurityException();
        }

        // 4. s2 = (h(m) + 秘密鍵z * s1)/k mod q
        // SEC.1 4.1.3 4. ハッシュ(パラメータhで済) 5. eの計算
        BigInteger e = signH(h); // hを切り詰めた値
        BigInteger s2 = e.add(prv.getS().multiply(s1)).mod(q).multiply(k.modInverse(q)).mod(q);
        if (s2.equals(BigInteger.ZERO)) {
            throw new SecurityException();
        }

        return bindSign(s1, s2, format);
    }

    /**
     * 上位有効ビットの取り出し.
     * バイト列を切り詰めたあと整数化する
     *
     * @param H ハッシュ値
     * @return Hをorderのビット長に切り詰めた値
     */
    protected BigInteger signH(byte[] H) {
        BigInteger q = E.getN(); // order
        Deterministic de = new Deterministic(q);
        return de.bits2int(H);
    }

    /**
     * 符号化.
     *
     * @param <T>
     * @param r
     * @param s
     * @param format 出力形式
     * @return
     */
    public <T> T bindSign(BigInteger r, BigInteger s, TypeFormat<T> format) {
        SEQUENCEMap m = new SEQUENCEMap();
        m.put("r", r);
        m.put("s", s);
        return (T) m.rebind(format);
    }

    /**
     * 複合.
     *
     * @param sign
     * @return r, s
     */
    public BigInteger[] pairDec(byte[] sign) {
        int blen = getKeyLength();
        if (sign.length != blen * 2) {
            throw new SecurityException();
        }
        BigInteger[] ss = new BigInteger[2];

        for (int i = 0; i < 2; i++) {
            byte[] S = Arrays.copyOfRange(sign, blen * i, blen * (i+1));
            ss[i] = PKCS1.OS2IP(S);
        }

        return ss;
    }

    /**
     *
     * @param sign
     * @return
     */
    @Override
    public boolean verify(byte[] sign) {
        try {
            BigInteger[] ss = pairDec((byte[])sign);
            return verify(ss);
        } catch (SecurityException e) {
            md.reset();
            return false;
        }
    }

    /**
     * KT-I verify
     *
     * @param sign (s1,s2) または (r, s) と表記するもの
     * @return 成否
     */
    public boolean verify(BigInteger[] sign) {
        BigInteger q = E.getN();
        byte[] h = md.digest();
        try {
            if (sign == null || sign.length != 2) {
                return false;
            }
        } catch (SecurityException e) {
            return false;
        }

        for (int i = 0; i < 2; i++) {
            if (sign[i].compareTo(BigInteger.ZERO) <= 0 || sign[i].compareTo(q) >= 0) {
                return false;
            }
        }
        BigInteger s1 = sign[0];
        BigInteger s2Inv = s2iv(sign[1], q);

        BigInteger hh = signH(h); // hを切り詰めた値
        
        BigInteger u1 = hh.multiply(s2Inv).mod(q);
        BigInteger u2 = s1.multiply(s2Inv).mod(q);
        ECCurvep.ECPoint Y = pub.getY();
        ECCurvep.ECPoint R = E.xG(u1).add(Y.x(u2));
        return R.getX().mod(q).equals(s1);
    }
    
    BigInteger s2iv(BigInteger s2, BigInteger q) {
        return s2.modInverse(q);
    }
}
