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
import java.security.SecureRandom;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.ietf.pkcs5.PBES2;
import net.siisise.ietf.pkcs5.PBES2params;
import net.siisise.ietf.pkcs5.PBKDF2params;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.security.block.AES;
import net.siisise.security.key.RSAPrivateCrtKey;
import net.siisise.security.mac.HMAC;

/**
 * PKCS #8 の後継的な
 * RFC 5208 PKCS #8 Private-Key Information Syntax Specification Version 1.2 私有鍵情報構文仕様 Version 1.2
 * RFC 5958 Asymmetric Key Packages
 */
public class RFC5958 extends PKCS8 {

    OBJECTIDENTIFIER hmac = HMAC.idhmacWithSHA256;
    OBJECTIDENTIFIER block = AES.aes256_CBC_PAD;
    int iterationCount = 2048;
    
    /**
     * RFC 5958 3.
     *
     * @param key RSA鍵
     * @param pass password
     * @return EncryptedPrivateKeyInfo
     * @throws NoSuchAlgorithmException
     */
    public SEQUENCEMap encryptedPrivateKeyInfoASN1(RSAPrivateCrtKey key, byte[] pass) throws NoSuchAlgorithmException {
        return encryptedPrivateKeyInfoASN1(key.getPKCS8PrivateKeyInfo(), pass);
    }

    /**
     * PrivateKeyInfo暗号化.
     *
     * @param info PKCS #8 PrivateKeyInfo
     * @param pass password
     * @return encryptedPrivateKeyInfo
     * @throws NoSuchAlgorithmException
     */
    public SEQUENCEMap encryptedPrivateKeyInfoASN1(PrivateKeyInfo info, byte[] pass) throws NoSuchAlgorithmException {
        return encryptPrivateKeyInfo(info.encodeASN1().encodeAll(), pass);
    }

    /**
     * PrivateKeyInfo 暗号付きASN.1符号化.
     *
     * @param key PKCS #8 PrivateKeyInfo
     * @param pass パスワード
     * @return 暗号化 EncryptedPrivateKeyInfo
     * @throws NoSuchAlgorithmException
     */
    SEQUENCEMap encryptPrivateKeyInfo(byte[] key, byte[] pass) throws NoSuchAlgorithmException {
        SecureRandom srnd = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[16];
        srnd.nextBytes(salt);
        byte[] iv = new byte[16];
        srnd.nextBytes(iv);
        PBKDF2params kdf2para = new PBKDF2params(salt, iterationCount, hmac);
        PBES2params es2para = new PBES2params(kdf2para, block, iv);

        PBES2 es = es2para.decode();
        es.init(pass);
        byte[] encdData = es.encrypt(key);

        AlgorithmIdentifier es2 = new AlgorithmIdentifier(PBES2.id_PBES2, es2para.encode());
        SEQUENCEMap s = new SEQUENCEMap();
        s.put("encryptionAlgorithm", es2.encodeASN1());
        s.put("encryptedData", new OCTETSTRING(encdData)); // あんごう
        return s;
    }

    /**
     * PrivateKeyInfo decode
     * @param src EncryptedPrivateKeyInfo
     * @param pass password
     * @return PKCS #8 PrivateKeyInfo
     */
    public static PrivateKeyInfo decryptPrivateKeyInfo(byte[] src, byte[] pass) {
        SEQUENCE s = (SEQUENCE) ASN1Util.toASN1(src);
        return decryptPrivateKeyInfo(s, pass);
    }

    /**
     * CMS RFC 5652, RFC 5083 を使って暗号化ができるのでどうにかする.
     * SignedData 署名 EncryptedData
     * AsymmetricKeyで暗号化 暗号化キー共有済み EnvelopedData AsymmetricKeyで暗号化 暗号化キーを共有しない
     * AuthenticatedData メッセージ認証コードを使用して EnvelopedDataと同様な AuthEnvelopedData
     * EnvelopedDataと同様な
     *
     * @param src EncryptedPrivateKeyInfo
     * @param pass password
     * @return PKCS #8 PrivateKeyInfo
     * @throws IOException
     */
    public static PrivateKeyInfo decryptPrivateKeyInfo(SEQUENCE s, byte[] pass) {
        AlgorithmIdentifier alg = AlgorithmIdentifier.decode((SEQUENCE) s.get(0));
        if (alg.algorithm.equals(PBES2.id_PBES2)) {
            PBES2params pbes2params = PBES2params.decode((SEQUENCE) alg.parameters);
            PBES2 es = pbes2params.decode();
            byte[] encryptedData = ((OCTETSTRING) s.get(1)).getValue();
            es.init(pass);
            byte[] key = es.decrypt(encryptedData);
            SEQUENCE seq = (SEQUENCE) ASN1Util.toASN1(key);
            return PrivateKeyInfo.decode(seq);
        }
        throw new UnsupportedOperationException();
    }

}
