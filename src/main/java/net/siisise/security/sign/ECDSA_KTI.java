/*
 * Copyright 2026 okome.
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
import net.siisise.security.ec.ECCurvep;
import net.siisise.security.ec.EllipticCurve;

/**
 * RFC 6090 5.4. KT-I Signatures
 * ElGamal署名っぽい KT-I署名.
 */
public class ECDSA_KTI extends ECDSA {

    /**
     * ElGamal署名っぽい KT-I署名.
     *
     * @param e 楕円曲線
     * @param h
     */
    public ECDSA_KTI(ECCurvep e, MessageDigest h) {
        super(e, h);
    }

    /**
     * KT-I署名をする.
     *
     * @param h メッセージmのハッシュ値
     * @param k 鍵
     * @return KT-I署名
     */
    @Override
    public byte[] sign(byte[] h, BigInteger k) {
        BigInteger q = E.getN(); // order

        // 2.
        // SEC.1 4.1.3. 1. kとRのペアを生成
        k = k.mod(q);
        EllipticCurve.ECPoint R = E.xG(k);
        // 3. s1 = r_x mod q
        BigInteger s1 = R.getX().mod(q);
        if (s1.equals(BigInteger.ZERO)) { // 5.
            throw new SecurityException();
        }

        // h を切り詰めた値
        BigInteger hh = signH(h);
        // 4.
        BigInteger s2 = hh.add(prv.getS().multiply(s1)).modInverse(k).mod(q);
        // 5.
        if (s2.equals(BigInteger.ZERO)) {
            throw new SecurityException();
        }

        return pairEnc(s1, s2);
    }

    /**
     * KT-I署名検証.
     *
     * @param sign 署名値
     * @return
     */
    @Override
    public boolean verify(byte[] sign) {
        BigInteger[] ss;
        try {
            ss = pairDec(sign);
        } catch (SecurityException e) {
            return false;
        }
        BigInteger s1 = ss[0];
        BigInteger q = E.getN();
        BigInteger s2 = ss[1].modInverse(q);

        BigInteger hh = signH(md.digest());

        BigInteger u1 = hh.multiply(s2).mod(q);
        BigInteger u2 = s1.multiply(s2).mod(q);

        EllipticCurve.ECPoint Y = pub.getY();
        EllipticCurve.ECPoint R = E.xG(u1).add(Y.x(u2));

        return R.getX().equals(s1);
    }

}
