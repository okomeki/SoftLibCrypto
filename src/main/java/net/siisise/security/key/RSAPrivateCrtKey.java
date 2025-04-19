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
import java.security.NoSuchAlgorithmException;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.ietf.pkcs8.EncryptedPrivateKeyInfo;
import net.siisise.ietf.pkcs8.PrivateKeyInfo;
import net.siisise.ietf.pkcs8.RFC5958;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 8017 PKCS #1 3.2. RSA Private Key.
 * 全要素使うパターン.
 * 公開鍵も作れる.
 * 証明書等は持っていない.
 * PKCS #1 と PKCS #8 のDERで出力可能
 * 
 * 作り方は RSAKeyGen
 * 
 * ToDo: まだ全部public
 */
public class RSAPrivateCrtKey extends RSAMiniPrivateKey implements java.security.interfaces.RSAPrivateCrtKey {

    private static final long serialVersionUID = 1L;

    int version; // 0か1 otherPrimeInfos が必要なとき 1

    final BigInteger publicExponent;   // e 公開
    /**
     * p : the first factor, a positive integer
     */
    final BigInteger prime1;           // p 秘密
    final BigInteger prime2;           // q 秘密
    final BigInteger exponent1;        // d mod (p-1) :dP : CRT (中国剰余定理) 指数 GARNER
    final BigInteger exponent2;        // d mod (q-1) :dQ
    final BigInteger coefficient;      // (inverse of q) mod p :qInv CRT 係数

    /**
     * 公開鍵が生成できる秘密鍵.
     * @param n modulus
     * @param e publicExponent
     * @param d privateExponent
     * @param p prime1
     * @param q prime2
     * @param dP exponent1
     * @param dQ exponent2
     * @param c coefficient
     */
    RSAPrivateCrtKey(BigInteger n, BigInteger e, BigInteger d, BigInteger p, BigInteger q,
            BigInteger dP, BigInteger dQ, BigInteger c) {
        super(n,d);
        publicExponent = e;
        prime1 = p;
        prime2 = q;
        exponent1 = dP;
        exponent2 = dQ;
        this.coefficient = c;
    }
    
    @Override
    public BigInteger getPublicExponent() {
        return publicExponent;
    }

    @Override
    public BigInteger getPrimeP() {
        return prime1;
    }

    @Override
    public BigInteger getPrimeQ() {
        return prime2;
    }

    @Override
    public BigInteger getPrimeExponentP() {
        return exponent1;
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        return exponent2;
    }

    @Override
    public BigInteger getCrtCoefficient() {
        return coefficient;
    }

    /**
     * 中国余剰定理.
     * エラー判定を省略して計算するだけ
     * 公開鍵側や(d &lt; e)の条件のときは失敗することがあるのかも
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

            BigInteger em = s.modPow(exponent1, prime1);
            BigInteger h = em.subtract(m).multiply(coefficient).mod(prime1);
            return m.add(prime2.multiply(h));
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
        if ( format == Format.PKCS1 ) { // RSA PRIVATE KEY
            return "PKCS#1";
        } else if ( format == Format.PKCS8 ) { // PRIVATE KEY
            return "PKCS#8";
//        } else if ( format == Format.PKCS8PEM ) {
//            return "PKCS#8PEM";
        }
        return "PKCS#8";
    }

    /**
     * 出力形式はいろいろあってもいい.
     * 公開鍵も出力できるが秘密鍵の形式のみ。
     */
    public static enum Format {
        PKCS1, // RFC 8017 A.1.2. DER
        PKCS8, // RFC 5208 BER ?  IDをふったもの
        RFC5958 //  RFC 5958 PKCS #8 の後継 PKCSの名がない 出力:DER 入力:DER/BER
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
     * 秘密鍵の出力.
     * PKCS#8 固定か他の形式も対応するか.
     * @return 
     */
    @Override
    public byte[] getEncoded() {
        if (format == Format.PKCS1) { // RSA PRIVATE KEY
            return getPKCS1Encoded();
        }
        return getPKCS8Encoded(); // PRIVATE KEY
    }

    /**
     * RFc 5208 PKCS 8 information
     * RFC 5958 2. Asymmetric Key Package CMS Content Type
     * @return 
     */
    public byte[] getPKCS8Encoded() {
        return getPKCS8PrivateKeyInfo().rebind(new ASN1DERFormat());
    }

    /**
     * PKCS #8 PrivateKeyInfo.
     * OpenSSL PRIVATE KEY
     * OBJECTIDENTIFIER が判別する容器に梱包したもの
     * RFC 5208 5. Private-Key Information Syntax
     * 
     * OID = rsaEncryption
     * 
     * PrivateKeyInfo ::= SEQUENCE {
     *   vrsion Version,
     *   privateKeyAlgorithm  PrivateKeyAlgorithmIdentifier,
     *   privateKey   PrivateKey,
     *   attributes     [0] IMPLICIT Attributes OPTIONAL }
     * 
     * Version ::= INTEGER
     * 
     * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     * 
     * PrivateKey :: = OCTET STRING
     * 
     * Attributes ::= SET OF Attribute
     * 
     * @return 形を真似しただけ
     */
    public PrivateKeyInfo getPKCS8PrivateKeyInfo() {
        byte[] body = getPKCS1Encoded(); // privateKey PrivateKey (BER / RFC 5208)
        return new PrivateKeyInfo(PKCS1.rsaEncryption, body);
    }

    /**
     * RFC 5958 版 PKCS #8 後継符号化.
     * PKCS #5 PBES2 で暗号化 
     * @param pass パスワード
     * @return 暗号化した
     */
    public EncryptedPrivateKeyInfo getRFC5958EncryptedPrivateKeyInfo(byte[] pass) {

        try {
            RFC5958 p8 = new RFC5958();
            return p8.encryptedPrivateKeyInfo(getPKCS8PrivateKeyInfo(), pass);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * RFC 8017 A.1.2.RSA Private Key Syntax.
     * Optional なし
     * @param <T>
     * @param format 
     * @return  
     */
    public <T> T rebind(TypeFormat<T> format) {
        SEQUENCEMap prv = getPKCS1ASN1();
        return (T)prv.rebind(format);
    }

    /**
     * RFC 8017 A.1.2. RSA Private Key Syntax
     * PKCS #1
     * 鍵の要素だけを格納したもの
     * @return ASN.1 DER 出力
     */
    public byte[] getPKCS1Encoded() {
        return rebind(new ASN1DERFormat());
    }

    /**
     * RFC 8017 RSA Private Key Syntax.
     * PKCS #1 A.1.2. で定義されている範囲のASN.1 DER 符号化
     * @return 
     */
    @Override
    public SEQUENCEMap getPKCS1ASN1() {
        SEQUENCEMap prv = new SEQUENCEMap();
        prv.put("version", 0); // 0: prime 1: multi 
        prv.put("modulus", modulus);
        prv.put("publicExponent", publicExponent);
        prv.put("privateExponent", privateExponent);
        prv.put("prime1", prime1);
        prv.put("prime2", prime2);
        prv.put("exponent1", exponent1);
        prv.put("exponent2", exponent2);
        prv.put("coefficient", coefficient);
        return prv;
    }
    
    /**
     * SSH系の鍵をいくつか出力できるようにしておくといいかもしれず
     * @return SSHの方式っぽい鍵
     * @deprecated いろいろあるのでまだ未定.
     */
    @Deprecated
    public byte[] getSSHEncoded() {
        throw new UnsupportedOperationException();
    }
    
    @Override
    public String toString() {
        return "Siisise RSA private CRT key, " + modulus.bitLength() + " bits";
    }
}
