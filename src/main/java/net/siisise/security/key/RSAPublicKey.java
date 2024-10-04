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
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.iso.asn1.tag.BITSTRING;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEList;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 8017 PKCS #1
 * RFC 4716 SSH Public Key
 */
public class RSAPublicKey implements java.security.interfaces.RSAPublicKey {

    private static final long serialVersionUID = 1L;
    /**
     * n modulus
     */
    private final BigInteger modulus;
    /**
     * e 公開指数
     */
    private final BigInteger publicExponent;

    /**
     * nとeで公開鍵をつくる
     * @param n modulus
     * @param e publicExponent
     */
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
     * n modulus を返す
     * @return n modulus
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

    public static enum Format {
        PKCS1, // RFC 8017 A.1.1.
        PKCS8,
//        X509,
//        SSH2, // RFC 4716 4253
    }
    
    /**
     * エンコードタイプ
     * @return 
     */
    @Override
    public String getFormat() {
        return "X.509";
    }
    
    @Override
    public byte[] getEncoded() {
        return getPKCS1Encoded();
    }

    /**
     * RSA Public Key Syntax.
     * RFC 8017 A.1.1. 
     * @return RFC 8017 A.1.1.形式のASN.1 DER
     */
    public byte[] getPKCS1Encoded() {
        return getPKCS1ASN1().encodeAll();
    }

    public SEQUENCEMap getPKCS1ASN1() {
/*      // rebind 任せでもいい
        return (SEQUENCE)rebind(new ASN1Convert());
/*/
        SEQUENCEMap pub = new SEQUENCEMap();
        pub.put("modules", modulus); // n
        pub.put("publicExponent", publicExponent); // e
        return pub;
//*/
    }
    
    /**
     * ASN.1 その他適度な型に変換する.
     * modulus と publicExponent のみ
     * @param <T> 出力型
     * @param format 出力先、書式
     * @return 出力
     */
    public <T> T rebind(TypeFormat<T> format) {
        SEQUENCEMap rsaPublicKey = new SEQUENCEMap();
        rsaPublicKey.put("modulus", modulus); // n
        rsaPublicKey.put("publicExponent", publicExponent); // e
        return format.mapFormat(rsaPublicKey);
    }
    
    /**
     * PKCS #8 PUBLIC KEY 非公式.
     * bit string のパターン
     * @return PKCS #8 DER
     */
    @Deprecated
    public byte[] getPKCS8Encoded() {
        return getPKCS8ASN1().encodeAll();
    }

    /**
     * rsaEncryption BITSTRINGのパターン.
     * PKCS #8など 非公式
     * @return OID + BITSTRING
     */
    @Deprecated
    public SEQUENCE getPKCS8ASN1() {
        SEQUENCE s = new SEQUENCEList();
        AlgorithmIdentifier aid = new AlgorithmIdentifier(PKCS1.rsaEncryption);
        s.add(aid.encodeASN1());
        s.add(new BITSTRING(getPKCS1Encoded()));
        return s;
    }

    /**
     * rsaEncryption X.509 証明書形式が一般的かな
     * OCTET STRING のパターン.
     * @deprecated まだ
     * @return 
     */
    @Deprecated
    public byte[] getRawEncoded() {
        SEQUENCE s = new SEQUENCEList();
        s.add(new INTEGER(0));
        AlgorithmIdentifier aid = new AlgorithmIdentifier(PKCS1.rsaEncryption);
        s.add(aid.encodeASN1());
        s.add(new OCTETSTRING(getPKCS1Encoded()));
        return s.encodeAll();
    }
        
    /**
     * RSA Encryption Primitive
     * 5.1.1. RSAEP
     * 暗号化.
     * 秘密鍵の RSADP と対
     * @param m メッセージ 0 から n-1の間の整数
     * @return 暗号 c 0 から n-1 の間の整数
     * @see RSAMiniPrivateKey#rsadp(java.math.BigInteger) 
     */
    public BigInteger rsaep(BigInteger m) {
        if ( m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(modulus) >= 0 ) {
            throw new SecurityException("message representative out of range");
        }
        return m.modPow(publicExponent, modulus);
    }

    /**
     * 暗号化.
     * 秘密鍵の RSADP と対
     * @param m メッセージ 0 から n-1の間の整数 のバイナリ
     * @return 暗号 c 0 から n-1 の間の整数
     */
    public BigInteger rsaep(byte[] m) {
        return rsaep(PKCS1.OS2IP(m));
    }
    
    /**
     * 入出力をbyte array にしたもの
     * @param m メッセージ 0 から n-1の間の整数
     * @param l 戻りオクテット長
     * @return 
     */
    public byte[] rsaep(byte[] m, int l) {
        return PKCS1.I2OSP(rsaep(PKCS1.OS2IP(m)), l);
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
    
    public byte[] rsavp1(byte[] s, int l) {
        return PKCS1.I2OSP( rsavp1(PKCS1.OS2IP(s)), l);
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
