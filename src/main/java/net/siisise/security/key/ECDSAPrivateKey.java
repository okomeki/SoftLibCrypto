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
package net.siisise.security.key;

import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.security.ec.EllipticCurve;
import net.siisise.security.sign.ECDSA;

/**
 * ECDSA 秘密鍵.
 * 曲線とパラメータx
 * RFC 5480
 */
public class ECDSAPrivateKey implements ECPrivateKey {

    final EllipticCurve.ECCurvep curve;
    final BigInteger d;

    /**
     * 曲線と秘密鍵.
     * FIPS 186-5 A.2
     * @param c 楕円曲線.
     * @param d 秘密鍵
     */
    public ECDSAPrivateKey(EllipticCurve.ECCurvep c, BigInteger d) {
        curve = c;
        this.d = d;//.mod(c.n);
    }

    public ECDSAPrivateKey(EllipticCurve.ECCurvep c, byte[] d) {
        curve = c;
        this.d = PKCS1.OS2IP(d);//.mod(c.n);
    }

    /**
     * 
     * @param spec 楕円曲線Fp
     * @param d 秘密鍵
     */
    public ECDSAPrivateKey(ECParameterSpec spec, BigInteger d) {
        curve = ECDSA.toCurve(spec);
        this.d = d;
    }

    /**
     * 
     * @param spec 楕円曲線Fp
     * @param d 秘密鍵
     */
    public ECDSAPrivateKey(ECParameterSpec spec, byte[] d) {
        curve = ECDSA.toCurve(spec);
        this.d = PKCS1.OS2IP(d);
    }

    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        return "ECDSA";
    }

    /**
     * d のみ.
     *
     * @return d
     */
    @Override
    public byte[] getEncoded() {
        return PKCS1.I2OSP(d, 0);
    }

    public AlgorithmIdentifier getAlgorithmIdentifier() {
        OBJECTIDENTIFIER oid = ECDSAPublicKey.ecPublicKey;
        ASN1Tag params;
        if (curve.oid != null) {
            params = curve.oid;
        } else {
            // implicitCurve
            // specifiedCurve
            throw new UnsupportedOperationException();
        }
        return new AlgorithmIdentifier(oid, params);
    }

    /**
     * 秘密鍵のみ.
     * @return 秘密鍵
     */
    public OCTETSTRING getPrivateKey() {
        return new OCTETSTRING(PKCS1.I2OSP(d, (curve.p.bitLength()+7)/8));
    }

    public EllipticCurve.ECCurvep getCurve() {
        return curve;
    }

    /**
     * 非公開値S.
     * FIPS 186-5 d
     * 
     * @return 秘密鍵の値
     */
    @Override
    public BigInteger getS() {
        return d;
    }

    /**
     * 曲線.
     * {
     *  curve: {
     *     field: {
     *        p
     *     }
     *     a,
     *     b
     *  }
     *  g,
     *  n,
     *  h
     * }
     * 
     * 
     * @return 曲線
     */
    @Override
    public ECParameterSpec getParams() {
        return ECDSA.toSpec(curve);
    }

    /**
     * FIPS 186-5 Q.
     * FIPS 186-5 A.2
     * 
     * 
     * @return Publick Key
     */
    public ECDSAPublicKey getPublicKey() {
        return new ECDSAPublicKey(curve,curve.xG(d));
    }

    @Override
    public boolean equals(Object o) {
        if ( o instanceof ECDSAPrivateKey) {
            ECDSAPrivateKey p = (ECDSAPrivateKey)o;
            return d.equals(p.d) && curve.equals(p.getCurve());
        }
        return false;
    }
}
