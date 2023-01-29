/*
 * Copyright 2022-2023 okome.
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
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;

/**
 * RFC 8017 PKCS #1
 */
public class RSAPublicKey implements java.security.interfaces.RSAPublicKey {

    private static final long serialVersionUID = 1L;
    private final BigInteger modulus;
    private final BigInteger publicExponent;

    public RSAPublicKey(BigInteger n, BigInteger e) {
        modulus = n;
        publicExponent = e;
    }

    /**
     * 公開指数.
     * @return public exponent
     */
    @Override
    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    /**
     * 
     * @return modulus
     */
    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    /**
     * RSA
     * @return "RSA"
     */
    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    /**
     * 
     * @return 
     */
    @Override
    public String getFormat() {
        return "X.509";
    }

    /**
     * X.509 証明書形式が一般的かな.
     * @return 
     */
    @Override
    public byte[] getEncoded() {
        SEQUENCE s = new SEQUENCE();
        s.add(new INTEGER(0));
        SEQUENCE v = new SEQUENCE();
        v.add(new OBJECTIDENTIFIER("1.2.840.113549.1.1.?"));
        v.add(new NULL());
        s.add(v);
        SEQUENCE pub = new SEQUENCE();
        pub.add(new INTEGER(modulus)); // n
        pub.add(new INTEGER(publicExponent)); // e
        s.add(new OCTETSTRING(pub.encodeAll()));
        return s.encodeAll();
    }

    /**
     * RSA Encryption Primitive
     * 5.1.1. RSAEP
     * 暗号化.
     * 秘密鍵の RSADP と対
     * @param m ブレーンテキスト
     * @return c 暗号
     * @see RSAMiniPrivateKey#rsadp(java.math.BigInteger) 
     */
    public BigInteger rsaep(BigInteger m) {
        if ( m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(modulus) >= 0 ) {
            throw new SecurityException("message representative out of range");
        }
        return m.modPow(publicExponent, modulus);
    }

    /**
     * 署名検証.
     * 5.2.2. RSAVP1
     * @param s 署名
     * @return 原文(ハッシュ)
     */
    public BigInteger rsavp1(BigInteger s) {
        if ( s.compareTo(BigInteger.ZERO) < 0 || s.compareTo(modulus) >= 0 ) {
            throw new SecurityException("signature representative out of range");
        }
        return s.modPow(publicExponent, modulus);
    }
    
    /**
     * 7.1.1. Encryption Opeation
     * mLen &lt;= k - 2hLen - 2
     * @param m key length
     * @param label 2^61 - 1 octets for SHA-1
     * @return C 長さkの暗号化テキスト
     */
/*
    BigInteger rsaes_oaep_encrypt(byte[] m, byte[] label) {
        // ラベル長エラーは省略する.
        // ToDo: メッセージ長チェックが必要
        MessageDigest md = new SHA1();
//        if (m.length > )
        
        
    }
*/
}
