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
import net.siisise.ietf.pkcs.asn1.PrivateKeyInfo;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;
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
    
    public static final OBJECTIDENTIFIER PKCS = new OBJECTIDENTIFIER("1.2.840.113549.1");
    public static final OBJECTIDENTIFIER PKCS1 = PKCS.sub(1);
    public static final OBJECTIDENTIFIER PKCS8 = PKCS.sub(8);
    public static final OBJECTIDENTIFIER rsaEncryption = PKCS1.sub(1);
    
    
    /**
     * 5. Private-Key Information Syntax
     * @param key 鍵をPKCS #8形式(暗号なし,DER)にする
     * @return 
     */
    public static SEQUENCE getPrivateKeyInfo(RSAPrivateCrtKey key) {
        PrivateKeyInfo info = new PrivateKeyInfo(rsaEncryption, key.getPKCS1Encoded());
        return info.encodeASN1();
    }

    /**
     * PKCS #8 DER をPrivateKeyに変換する
     * @param src
     * @return
     * @throws IOException 
     */
    public static RSAPrivateCrtKey setPrivateKeyInfo(byte[] src) throws IOException {
        PrivateKeyInfo info = PrivateKeyInfo.decode((SEQUENCE) ASN1Util.toASN1(src));
        if ( info.version == 0 && rsaEncryption.equals(info.privateKeyAlgorithm.algorithm) ) {
            return RSAKeyGen.decodeSecret1(info.privateKey);
        }
        throw new java.lang.UnsupportedOperationException("Invalid OID");
    }

    /**
     * 
     * @param key
     * @param pass
     * @return 
     */
    public static SEQUENCE getEncryptedPrivateKeyInfo(RSAPrivateCrtKey key, byte[] pass) {
        throw new UnsupportedOperationException();
    } 
    
    public static RSAPrivateCrtKey getDecryptedPrivateKeyInfo(byte[] src, byte[] pass) {
        throw new UnsupportedOperationException();
    }
    
}
