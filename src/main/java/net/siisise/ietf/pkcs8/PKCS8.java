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
package net.siisise.ietf.pkcs8;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import net.siisise.ietf.pkcs5.PBES2;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.security.key.RSAPrivateCrtKey;
import net.siisise.security.key.RSAKeyGen;

/**
 * しばらく5958より5208重視.
 * RSA暗号キーを保存する形式のひとつ.
 * ASN.1形式(BER, DER / PEM)、暗号化したASN.1形式の2パターンぐらいある。
 * RFC 5208 Public-Key Cryptography Standard (PKCS) #8
 *  Private-Key Information Syntax Specification Version 1.2
 * RFC 5958 Asymmetric Key Packages
 * RFC 8479
 */
public class PKCS8 {
    
    public static final OBJECTIDENTIFIER PKCS = net.siisise.ietf.pkcs1.PKCS1.PKCS; // new OBJECTIDENTIFIER("1.2.840.113549.1");
    public static final OBJECTIDENTIFIER PKCS1 = net.siisise.ietf.pkcs1.PKCS1.PKCS1;
    public static final OBJECTIDENTIFIER rsaEncryption = net.siisise.ietf.pkcs1.PKCS1.rsaEncryption;
    public static final OBJECTIDENTIFIER PKCS8 = PKCS.sub(8);
    
    /**
     * 5. Private-Key Information Syntax
     * @param key 鍵をPKCS #8形式(暗号なし,DER)にする
     * @return PrivateKeyInfo PKCS #8でラップした鍵
     */
    public static SEQUENCEMap getPrivateKeyInfo(RSAPrivateCrtKey key) {
        PrivateKeyInfo info = new PrivateKeyInfo(rsaEncryption, key.getPrivateEncoded());
        return info.encodeASN1();
    }

    /**
     * PKCS #8 DER をPrivateKeyに変換する
     * @param src ASN.1 DER 型 PKCS #8 PrivateKeyInfo
     * @return Java 鍵型
     * @throws IOException 未サポート等
     */
    public static RSAPrivateCrtKey setPrivateKeyInfo(byte[] src) throws IOException {
        PrivateKeyInfo info = PrivateKeyInfo.decode((SEQUENCE) ASN1Util.toASN1(src));
        if ( info.version == 0 && rsaEncryption.equals(info.privateKeyAlgorithm.algorithm) ) {
            return RSAKeyGen.decodeSecret1(info.privateKey);
        }
        throw new java.lang.UnsupportedOperationException("Invalid OID");
    }

    /**
     * RFC 5958 3.
     *
     * @deprecated 鍵別に移動
     * @param key RSA鍵
     * @param pass password
     * @return EncryptedPrivateKeyInfo
     * @throws NoSuchAlgorithmException 該当アルゴリズムなし
     */
    @Deprecated
    public SEQUENCEMap encryptedPrivateKeyInfoASN1(RSAPrivateCrtKey key, byte[] pass) throws NoSuchAlgorithmException {
        return encryptedPrivateKeyInfo(key.getPKCS8PrivateKeyInfo(), pass).encode();
    }

    /**
     * PrivateKeyInfo暗号化.
     *
     * @param info PKCS #8 PrivateKeyInfo
     * @param pass password
     * @return encryptedPrivateKeyInfo
     * @throws NoSuchAlgorithmException 該当アルゴリズムなし
     */
    public EncryptedPrivateKeyInfo encryptedPrivateKeyInfo(PrivateKeyInfo info, byte[] pass) throws NoSuchAlgorithmException {
        return encryptPrivateKeyInfo(info.encodeASN1().encodeAll(), pass);
    }

    EncryptedPrivateKeyInfo encryptPrivateKeyInfo(byte[] keyInfo, byte[] pass) throws NoSuchAlgorithmException {
        throw new UnsupportedOperationException();
    }

    /**
     * PrivateKeyInfo decode
     *
     * @param src EncryptedPrivateKeyInfo
     * @param pass password
     * @return PKCS #8 PrivateKeyInfo
     */
    public PrivateKeyInfo decryptPrivateKeyInfo(byte[] src, byte[] pass) {
        byte[] m = PBES2.decryptAll(src, pass);
        SEQUENCE s = (SEQUENCE) ASN1Util.toASN1(m);
        return OneAsymmetricKey.decode(s);
    }

    public PrivateKeyInfo decryptPrivateKeyInfo(SEQUENCE src, byte[] pass) {
        return decryptPrivateKeyInfo(EncryptedPrivateKeyInfo.decode(src), pass);
    }

    public PrivateKeyInfo decryptPrivateKeyInfo(EncryptedPrivateKeyInfo info, byte[] pass) {
        return new RFC5958().decryptPrivateKeyInfo(info, pass);
    }
}
