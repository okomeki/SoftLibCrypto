/*
 * Copyright 2023 okome.
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

import java.io.Serializable;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEList;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 8017 PKCS #1 3.2. RSA Private Key.
 * 全要素使うパターン.
 * 公開鍵も作れる.
 * 証明書等は持っていない.
 *
 * 作り方は RSAKeyGen
 * 
 * ToDo: まだ全部public
 */
public class RSAMultiPrivateKey extends RSAPrivateCrtKey {

    /**
     * A.1.2.
     */
    public static class OtherPrimeInfo implements Serializable {
        public BigInteger prime;        // r
        public BigInteger exponent;     // d
        public BigInteger coefficient;  // t
        
        void decode(SEQUENCE seq) {
            prime = ((INTEGER)seq.get(0)).getValue();
            exponent = ((INTEGER)seq.get(1)).getValue();
            coefficient = ((INTEGER)seq.get(2)).getValue();
        }
        
        SEQUENCEMap encode() {
            SEQUENCEMap info = new SEQUENCEMap();
            info.put("prime", prime);
            info.put("exponent", exponent);
            info.put("coefficient", coefficient);
            return info;
        }
        
        public <T> T rebind(TypeFormat<T> format) {
            LinkedHashMap info = new LinkedHashMap();
            info.put("prime", prime);
            info.put("exponent", exponent);
            info.put("coefficient", coefficient);
            return format.mapFormat(info);
        }
    }

    OtherPrimeInfo[] otherPrimeInfos; // OPTIONAL

    /**
     * 
     * @param n modulus
     * @param e publicExponent
     * @param d privateExponent
     * @param p prime1
     * @param q prime2
     * @param dP exponent1
     * @param dQ exponent2
     * @param coefficient coefficient
     * @param op other prime info
     */
    public RSAMultiPrivateKey(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q, BigInteger dP, BigInteger dQ, BigInteger coefficient,
            List<OtherPrimeInfo> op) {
        super(n, e, d, p, q, dP, dQ, coefficient);
        otherPrimeInfos = op.toArray(new OtherPrimeInfo[op.size()]);
    }

    /**
     * 中国余剰定理.
     * エラー判定を省略して計算するだけ
     * s.modPow(privateExponent, modulus) s.modPow(e, n)と同等 
     * c to m
     * m to s
     * @param s c または m
     * @return m または s
     */
    @Override
    public BigInteger modPow(BigInteger s) {
        if (coefficient == null) { // a.
            return s.modPow(privateExponent, modulus);
        } else { // b.
            // 細かい鍵があるターン.
            BigInteger m = s.modPow(exponent2, prime2);
            BigInteger R = prime2;

            BigInteger em = s.modPow(exponent1, prime1);
            BigInteger h = em.subtract(m).multiply(coefficient).mod(prime1);
            m = m.add(R.multiply(h));

            if ( version > 0 ) {
                BigInteger op = prime1;
                for (OtherPrimeInfo pi : otherPrimeInfos) {
                    R = R.multiply(op);
                    em = s.modPow(pi.exponent, pi.prime);
                    h = em.subtract(m).multiply(pi.coefficient).mod(pi.prime);
                    m = m.add(R.multiply(h));
                    op = pi.prime;
                }
            }

            return m;
        }
    }

    /**
     * RFC 8017 RSA Private Key Syntax.
     * PKCS #1 A.1.2. で定義されている範囲のASN.1 DER 符号化
     * @return 
     */
    @Override
    public SEQUENCEMap getPKCS1ASN1() {
        SEQUENCEMap prv = new SEQUENCEMap();
        prv.put("version", version);
        prv.put("modulus", modulus);
        prv.put("publicExponent", publicExponent);
        prv.put("privateExponent", privateExponent);
        prv.put("prime1", prime1);
        prv.put("prime2", prime2);
        prv.put("exponent1", exponent1);
        prv.put("exponent2", exponent2);
        prv.put("coefficient", coefficient);
        if ( version > 0 ) {
            SEQUENCEList ots = new SEQUENCEList(); // SEQUENCE OF OtherPrimeInfo
            for ( OtherPrimeInfo pi : otherPrimeInfos ) {
                ots.add(pi.encode());
            }
            prv.put("otherPrimeInfos", ots);
        }
        return prv;
    }

    /**
     * RFC 8017 PKCS #1 A.1.2.
     * 
     * ASN.1 と同じ出力を他フォーマットでも可能に
     * @param <T>
     * @param format 
     * @return 
     */
    @Override
    public <T> T rebind(TypeFormat<T> format) {
        LinkedHashMap prv = new LinkedHashMap();
        prv.put("version", version);
        prv.put("modulus", modulus);
        prv.put("publicExponent", publicExponent);
        prv.put("privateExponent", privateExponent);
        prv.put("prime1", prime1);
        prv.put("prime2", prime2);
        prv.put("exponent1", exponent1);
        prv.put("exponent2", exponent2);
        prv.put("coefficient", coefficient);
        if ( version > 0 ) {
            List ots = Arrays.asList(otherPrimeInfos);
            prv.put("otherPrimeInfos", ots);
        }
        return format.mapFormat(prv);
    }

    @Override
    public String toString() {
        return "Siisise RSA private CRT key, " + modulus.bitLength() + " bits";
    }
}
