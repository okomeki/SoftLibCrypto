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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;

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
public class RSAFullPrivateKey extends RSAMiniPrivateKey {

    /**
     * A.1.2.
     */
    public static class OtherPrimeInfo {
        public BigInteger prime;        // r
        public BigInteger exponent;     // d
        public BigInteger coefficient;  // t
    }
    
    private static final long serialVersionUID = 1L;

    int version; // 0か1 otherPrimeInfos が必要なとき 1

    BigInteger publicExponent;   // e 公開
    /**
     * p : the first factor, a positive integer
     */
    BigInteger prime1;           // p 秘密
    BigInteger prime2;           // q 秘密
    BigInteger exponent1;        // d mod (p-1) :dP : CRT (中国剰余定理) 指数 GARNER
    BigInteger exponent2;        // d mod (q-1) :dQ
    BigInteger coefficient;      // (inverse of q) mod p :qInv CRT 係数
    List<OtherPrimeInfo> otherPrimeInfos = new ArrayList<>(); // OPTIONAL

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
     * 全要素ある場合.
     * 秘密鍵要素のみ抽出してみたり.
     *
     * @return n, dのみ
     */
    public RSAMiniPrivateKey getPrivateKey() {
        return new RSAMiniPrivateKey(modulus, privateExponent);
    }

    /**
     * 公開鍵要素も持っている.
     * @return 公開鍵(鍵のみ)
     */
    public RSAPublicKey getPublicKey() {
        return new RSAPublicKey(modulus, publicExponent);
    }

    /**
     * PKCS#12は PKCS#8?
     * @return 
     */
    @Override
    public String getFormat() {
        if ( format == Format.PKCS1 ) {
            return "PKCS#1";
        } else if ( format == Format.PKCS8 ) {
            return "PKCS#8";
//        } else if ( format == Format.PKCS8PEM ) {
//            return "PKCS#8PEM";
        }
        return "PKCS#8";
    }

    /**
     * 出力形式はいろいろあってもいい.
     */
    public static enum Format {
        PKCS1, // RFC 8017 DER
        PKCS8, // DER
//        PKCS8PEM // PEM (予定)
    }

    Format format = Format.PKCS8;

    /**
     * 特殊機能? PKCS #1形式でも出力できるような
     * @param f 
     */
    public void setFormat(Format f) {
        format = f;
    }

    /**
     * PKCS#8 固定か他の形式も対応するか.
     * @return 
     */
    @Override
    public byte[] getEncoded() {
        if (format == Format.PKCS1) {
            return getPKCS1Encoded();
        }
        return getPKCS8Encoded();
    }

    /**
     * PKCS #8 DER ぐらい
     * @return 形を真似しただけ
     */
    public byte[] getPKCS8Encoded() {
        SEQUENCE s = new SEQUENCE();
        s.add(new INTEGER(0));
        SEQUENCE ids = new SEQUENCE();
        ids.add(new OBJECTIDENTIFIER("1.2.840.113549.1.1.1"));
        ids.add(new NULL());
        s.add(ids);
        s.add(new OCTETSTRING(getPKCS1Encoded()));
        return s.encodeAll();
    }

    /**
     * PKCS #1 で定義されている範囲のASN.1 DER 符号化
     * @return 
     */
    public byte[] getPKCS1Encoded() {
        SEQUENCE prv = new SEQUENCE();
        prv.add(new INTEGER(version));
        prv.add(new INTEGER(modulus));
        prv.add(new INTEGER(publicExponent));
        prv.add(new INTEGER(privateExponent));
        prv.add(new INTEGER(prime1));
        prv.add(new INTEGER(prime2));
        prv.add(new INTEGER(exponent1));
        prv.add(new INTEGER(exponent2));
        prv.add(new INTEGER(coefficient));
        if ( version > 0 ) {
            SEQUENCE ots = new SEQUENCE();
            for ( OtherPrimeInfo pi : otherPrimeInfos ) {
                SEQUENCE dpi = new SEQUENCE();
                dpi.add(new INTEGER(pi.prime));
                dpi.add(new INTEGER(pi.exponent));
                dpi.add(new INTEGER(pi.coefficient));
                ots.add(dpi);
            }
            prv.add(ots);
        }
        return prv.encodeAll();
    }
    
    @Override
    public String toString() {
        return "Siisise RSA private CRT key, " + modulus.bitLength() + " bits";
    }
}
