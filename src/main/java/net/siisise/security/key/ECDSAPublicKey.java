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
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.BITSTRING;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.security.ec.ECCurve;
import net.siisise.security.ec.EllipticCurve;
import net.siisise.security.sign.ECDSA;

/**
 * まだ限定 ECCurvep FIPS 186-5 Public Key Q
 */
public class ECDSAPublicKey implements ECPublicKey {

    public static final OBJECTIDENTIFIER ecPublicKey = new OBJECTIDENTIFIER("1.2.840.10045.2.1");
    public static final OBJECTIDENTIFIER ecDH = new OBJECTIDENTIFIER("1.3.132.1.12");
    public static final OBJECTIDENTIFIER ecMQV = new OBJECTIDENTIFIER("1.3.132.1.13");

    AlgorithmIdentifier algorithm;
    ECCurve curve;
    ECParameterSpec spec;
    final EllipticCurve.ECPoint Q;

    public ECDSAPublicKey(ECParameterSpec spec, ECPoint p) {
        this.spec = spec;
        curve = ECDSA.toCurve(spec);
        Q = curve.toPoint(p.getAffineX(), p.getAffineY());
    }

    public ECDSAPublicKey(ECCurve curve, BigInteger x, BigInteger y) {
        this.curve = curve;
        Q = curve.toPoint(x, y);
    }

    /**
     *
     * @param curve
     * @param q 公開鍵座標 add,y
     */
    public ECDSAPublicKey(ECCurve curve, EllipticCurve.ECPoint q) {
        this.curve = curve;
        Q = q;
    }

    /**
     * 同じ曲線バラメータであるか
     *
     * @param o
     * @return
     */
    @Override
    public boolean equals(Object o) {
        if (o instanceof ECPublicKey) {
            ECPublicKey p = (ECPublicKey) o;
            return p.getAlgorithm().equals("EC") && p.getParams().equals(ECDSA.toSpec(curve)) && p.getW().equals(getW());
        }
        return false;
    }

    /**
     * 公開鍵座標 for Java
     *
     * @return 公開鍵
     */
    @Override
    public ECPoint getW() {
        return new ECPoint(Q.getX(), Q.getY());
    }

    /**
     * FIPS 186-5 Q. 公開鍵座標
     *
     * @return
     */
    public EllipticCurve.ECPoint getY() {
        return Q;
    }

    public ECCurve getCurve() {
        return curve;
    }

    /**
     * ECDSAはEC.
     *
     * @return "EC"
     */
    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public <T> T rebind(TypeFormat<T> format) {
        // RFC 5480 2.
        // SubjectPublicKeyInfo
        SEQUENCEMap info = new SEQUENCEMap();

        AlgorithmIdentifier ai;
        if (algorithm == null) {
            ai = new AlgorithmIdentifier(ecPublicKey, null);
        } else {
            ai = algorithm;
        }
        OBJECTIDENTIFIER alg = algorithm.algorithm;
        // RFC 5480 2.1.1
        if (curve.getOID() != null) {
            ai.parameters = curve.getOID();
        } else {
            throw new UnsupportedOperationException("RFC 5480 2.1.1 MUST NOT");
        }
        info.put("algorithm", ai);
        byte[] oct = Q.encXY(); // 非圧縮04XY
        info.put("subjectPublicKey", new BITSTRING(oct));
        return (T) info.rebind(format);
    }

    @Override
    public ECParameterSpec getParams() {
        return spec == null ? ECDSA.toSpec(curve) : spec;
    }

}
