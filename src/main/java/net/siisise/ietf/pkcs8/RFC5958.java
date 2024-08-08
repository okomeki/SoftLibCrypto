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
import net.siisise.bind.Rebind;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.ietf.pkcs5.PBES2;
import net.siisise.ietf.pkcs5.PBES2params;
import net.siisise.ietf.pkcs5.PBKDF2;
import net.siisise.iso.asn1.ASN1Object;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEList;
import net.siisise.security.block.AES;
import net.siisise.security.digest.SHA256;
import net.siisise.security.key.RSAPrivateCrtKey;
import net.siisise.security.mac.HMAC;
import net.siisise.security.mode.CBC;

/**
 * PKCS #8 の後継的な
 * RFC 5258 PKCS #8
 * RFC 5958
 */
public class RFC5958 extends PKCS8 {

    static OBJECTIDENTIFIER USGOV = new OBJECTIDENTIFIER("2.16.840.1.101");
//    static OBJECTIDENTIFIER id_ct_KP_aKeyPackage = USGOV.sub(2,1,2,78,5);
    static OBJECTIDENTIFIER AES = USGOV.sub(3,4,1);
    /**
     * 
     * @param key
     * @param pass
     * @return
     * @throws NoSuchAlgorithmException 
     */
    public SEQUENCE getRFC5958EncryptedPrivateKeyInfoASN1(RSAPrivateCrtKey key, byte[] pass) throws NoSuchAlgorithmException {
        SecureRandom srnd = SecureRandom.getInstanceStrong();
        byte[] salt = new byte[16];
        srnd.nextBytes(salt);
        int c = 2048;
        PBKDF2 kdf = new PBKDF2(new HMAC(new SHA256()));
        CBC block = new CBC(new AES());
        byte[] iv = new byte[16];
        srnd.nextBytes(iv);
        PBES2 es = new PBES2(kdf);
        es.setParam(iv);
        es.init(block, pass, salt, c);
        byte[] encdData = es.encrypt(key.getPKCS1Encoded());
        ASN1Convert format = new ASN1Convert();

        SEQUENCE s = new SEQUENCEList();
         AlgorithmIdentifier es2 = new AlgorithmIdentifier();
         es2.algorithm = PBES2.id_PBES2;
           SEQUENCE esPara = new SEQUENCEList(); // 0,1
         es2.parameters = esPara;
             AlgorithmIdentifier kdfai = new AlgorithmIdentifier();
             kdfai.algorithm = PBKDF2.OID;
               SEQUENCE kdfparams = new SEQUENCEList(); // 0,1,0,1
             kdfai.parameters = kdfparams;
               kdfparams.add(new OCTETSTRING(salt));
               kdfparams.add(new INTEGER(c));
                 AlgorithmIdentifier ss = new AlgorithmIdentifier();
                 ss.algorithm = HMAC.idhmacWithSHA256;
               kdfparams.add(ss.encodeASN1());
           esPara.add(kdfai.encodeASN1()); // 0.1.0
             AlgorithmIdentifier enc = new AlgorithmIdentifier();
             enc.algorithm = AES.sub(42); // aes256-CBC-PAD
             enc.parameters = new OCTETSTRING(iv);
           esPara.add(enc.encodeASN1()); // 0.1.1
        s.add(es2.encodeASN1());
        s.add(new OCTETSTRING(encdData)); // あんごう
        return s;
    }
    
    /**
     * CMS RFC 5652, RFC 5083 を使って暗号化ができるのでどうにかする.
     * SignedData 署名
     * EncryptedData AsymmetricKeyで暗号化 暗号化キー共有済み
     * EnvelopedData AsymmetricKeyで暗号化 暗号化キーを共有しない
     * AuthenticatedData メッセージ認証コードを使用して  EnvelopedDataと同様な
     * AuthEnvelopedData EnvelopedDataと同様な
     * @param src
     * @param pass
     * @return
     * @throws IOException 
     */
    public static RSAPrivateCrtKey decrypt(byte[] src, byte[] pass) throws IOException {
        SEQUENCE s = (SEQUENCE) ASN1Util.toASN1(src);
        System.out.println(s.getClass().getName());
        System.out.println(s);
        
        AlgorithmIdentifier alg = AlgorithmIdentifier.decode((SEQUENCE) s.get(0));
        if ( alg.algorithm.equals(PBES2.id_PBES2)) {
            PBES2params pbes2params = PBES2params.decode((SEQUENCE) alg.parameters);
            PBES2 es = pbes2params.decode();
            ASN1Object kdfid = pbes2params.keyDerivationFunc.algorithm;
            byte[] enc = ((OCTETSTRING)s.get(1)).getValue();
            es.init(pass);
            byte[] dec = es.decrypt(enc);
            SEQUENCE seq = (SEQUENCE)ASN1Util.toASN1(dec);
            System.out.println(seq);
        }
        throw new UnsupportedOperationException();
    }
    
}
