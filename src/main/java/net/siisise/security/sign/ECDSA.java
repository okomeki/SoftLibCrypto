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
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.io.Output;
import net.siisise.io.PacketA;
import net.siisise.security.ec.EllipticCurve;
import net.siisise.security.key.ECDSAPrivateKey;
import net.siisise.security.key.ECDSAPublicKey;

/**
 * ECDSA.
 * RFC 6090 楕円曲線
 * 曲線と署名用ハッシュ関数、秘密鍵または公開鍵を持つ
 */
public class ECDSA extends Output.AbstractOutput implements SignVerify {

    MessageDigest md;
    ECDSAPrivateKey prv;
    ECDSAPublicKey pub;

    EllipticCurve.ECCurvep E;

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
            throw new UnsupportedOperationException();
        }
    }
    
    public static ECParameterSpec toSpec(EllipticCurve.ECCurvep curve) {
        ECFieldFp Fp = new ECFieldFp(curve.p);
        java.security.spec.EllipticCurve c = new java.security.spec.EllipticCurve(Fp,curve.a,curve.b);
        ECPoint g = new ECPoint(curve.G.getX(), curve.G.getY());
        return new ECParameterSpec(c, g, curve.n, curve.h);
    }
    
    public static ECDSAPrivateKey toECDSAKey(ECPrivateKey prv) {
        EllipticCurve.ECCurvep curve = toCurve(prv.getParams());
        BigInteger s = prv.getS();
        return new ECDSAPrivateKey(curve, s);
    }
    
    public static ECDSAPublicKey toECDSAKey(ECPublicKey pub) {
        EllipticCurve.ECCurvep curve = toCurve(pub.getParams());
        ECPoint Y = pub.getW();
        return new ECDSAPublicKey(curve, Y.getAffineX());
        
    }
    /**
     * 
     * @param e 楕円曲線E
     * @param h ハッシュ関数
     */
    public ECDSA(EllipticCurve.ECCurvep e, MessageDigest h) {
        this.E = e;
        this.md = h;
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
        return (E.p.bitLength() + 7)/ 8;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        md.update(src, offset, length);
    }
    
    BigInteger rnd() {
        int bit = prv.getCurve().p.bitLength(); // てきとうに増やす
        byte[] rnd = new byte[(bit+9)/8];
        try {
            SecureRandom.getInstanceStrong().nextBytes(rnd);
            rnd[0] &= 0x7f;
            return new BigInteger(rnd);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /**
     * KT-I 方式.
     * 
     * @return 
     */
    @Override
    public byte[] sign() {
        byte[] digest = md.digest();
        BigInteger h = PKCS1.OS2IP(digest);
        EllipticCurve.ECCurvep curve = prv.getCurve();
        // 1 <= k < n
        
        int blen = (curve.p.bitLength()+7)/8;
        
        do {
            BigInteger k = rnd().mod(curve.n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        
            EllipticCurve.Point R = curve.xG(k.mod(curve.n));
            BigInteger s1 = R.getX().mod(curve.n);
            if ( s1.equals(BigInteger.ZERO) ) continue;
            BigInteger s2 = h.add(prv.getS().multiply(s1).mod(curve.n));
            if ( s2.equals(BigInteger.ZERO) ) continue;

            PacketA pac = new PacketA();
            pac.write(PKCS1.I2OSP(s1, blen));
            pac.write(PKCS1.I2OSP(s2, blen));
            return pac.toByteArray();
        } while (true);
    }

    @Override
    public boolean verify(byte[] sign) {
        byte[] digest = md.digest();
        BigInteger h = PKCS1.OS2IP(digest);
        EllipticCurve.ECCurvep curve = pub.getCurve();
        ECPoint Y = pub.getW();

        int blen = (curve.p.bitLength()+7)/8;
        if (sign.length != blen*2) return false;
        PacketA sgn = new PacketA(sign);
        byte[] b = new byte[blen];
        sgn.read(b);
        BigInteger s1 = PKCS1.OS2IP(b);
        sgn.read(b);
        BigInteger s2inv = PKCS1.OS2IP(b).modInverse(curve.n);

        BigInteger u1 = h.multiply(s2inv).mod(curve.n);
        BigInteger u2 = s1.multiply(s2inv).mod(curve.n);
//        curve.x(curve.xG(u1),curve.x(u2, Y);
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
