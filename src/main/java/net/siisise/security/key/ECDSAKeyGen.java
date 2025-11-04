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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.ec.ECCurvep;
import net.siisise.security.ec.EllipticCurve;

/**
 * FIPS PUB 186-5 ?
 */
public class ECDSAKeyGen {

    public ECDSAPrivateKey genPrivateKey(ECCurvep curve) {
        BigInteger x;
        try {
            SecureRandom srnd = SecureRandom.getInstanceStrong();
            BigInteger s = new BigInteger(curve.p.bitLength()*2, srnd); // 1 <= x < n
            x = s.mod(curve.n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            return new ECDSAPrivateKey(curve, x);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * PKCS #8 の privateKey  OCTETSTRING からデコード.
     * @param ai
     * @param prv privateKey OCTETSTRING の中身
     * @return 
     */
    public static ECDSAPrivateKey decodePrivate(AlgorithmIdentifier ai, byte[] prv) {
        ECCurvep curve = toCurve(ai);
        return new ECDSAPrivateKey(curve, prv);
    }

    /**
     * 公開鍵変換.
     * @param ai 曲線
     * @param pub 点 publicKey BITSTRING の中相当
     * @return 公開鍵
     */
    public ECDSAPublicKey decodePublic(AlgorithmIdentifier ai, byte[] pub) {
        ECCurvep curve = toCurve(ai);
        ECCurvep.ECPointp p = curve.toPoint(pub);
        return new ECDSAPublicKey(curve, p);
    }

    /**
     * アルゴリズムから曲線の取得.
     * @param ai 
     * @return 
     */
    static ECCurvep toCurve(AlgorithmIdentifier ai) {
        if ( ai.parameters instanceof OBJECTIDENTIFIER) {
            return getCurve((OBJECTIDENTIFIER)ai.parameters);
        }
        
        throw new UnsupportedOperationException();
    }

    static Map<OBJECTIDENTIFIER, ECCurvep> curves = new HashMap<>();
    
    static {
        curves.put(EllipticCurve.P192.oid, EllipticCurve.P192);
        curves.put(EllipticCurve.P224.oid, EllipticCurve.P224);
        curves.put(EllipticCurve.P256.oid, EllipticCurve.P256);
        curves.put(EllipticCurve.P384.oid, EllipticCurve.P384);
        curves.put(EllipticCurve.P521.oid, EllipticCurve.P521);
        curves.put(EllipticCurve.secp256k1.oid, EllipticCurve.secp256k1);
    }

    private static ECCurvep getCurve(OBJECTIDENTIFIER oid) {
        return curves.get(oid);
    }
}
