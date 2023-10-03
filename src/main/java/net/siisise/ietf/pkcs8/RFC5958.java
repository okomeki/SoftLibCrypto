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
import net.siisise.ietf.pkcs5.PBKDF2;
import net.siisise.ietf.pkcs5.PBKDF2params;
import net.siisise.iso.asn1.ASN1Object;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;
import net.siisise.security.digest.SHA256;
import net.siisise.security.key.RSAPrivateCrtKey;
import net.siisise.security.mac.HMAC;
import net.siisise.security.mac.MAC;
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
        byte[] salt = srnd.generateSeed(8);
        int c = 2048;
        PBKDF2 kdf = new PBKDF2(new HMAC(new SHA256()));
        CBC block = new CBC(new AES());
        PBES2 es = new PBES2(kdf);
        es.init(block, pass, salt, c);
        SEQUENCE s = new SEQUENCE();
         SEQUENCE ids = new SEQUENCE(); // 0 AlgorithmIdentifier
          ids.add(PBES2.id_PBES2); // 0,0
          SEQUENCE s1 = new SEQUENCE(); // 0,1
           SEQUENCE s2 = new SEQUENCE(); //0,1,0
           s2.add(PBKDF2.OID); // 0,1,0,0
            SEQUENCE s3 = new SEQUENCE(); // 0,1,0,1
            s3.add(new OCTETSTRING(salt));
            s3.add(new INTEGER(c));
             SEQUENCE s4 = new SEQUENCE();
             s4.add(new OBJECTIDENTIFIER(HMAC.idhmacWithSHA256)); // HMACwithSHA256
             s4.add(new NULL());
            s3.add(s4);
           s2.add(s3); // 0,1,0,1
          s1.add(s2); // 0.1.0
           s2 = new SEQUENCE();
           s2.add(AES.sub(42)); // aes256-CBC-PAD
           s2.add(new OCTETSTRING(new byte[16])); // パラメータ aes鍵? iv?
          s1.add(s2); // 0.1.1
         ids.add(s1); // 0.1
        s.add(ids);
        s.add(new OCTETSTRING(new byte[1232])); // あんごう
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
            ASN1Object kdfid = pbes2params.keyDerivationFunc.algorithm;
            PBES2 es = new PBES2();
            if ( kdfid.equals(PBKDF2.OID)) {
                PBKDF2 kdf = new PBKDF2();
                PBKDF2params pbkdf2params = PBKDF2params.decode((SEQUENCE) pbes2params.keyDerivationFunc.parameters);
                byte[] salt = ((OCTETSTRING)pbkdf2params.salt).getValue();
                int c = ((INTEGER)pbkdf2params.iterationCount).getValue().intValue();
                MAC hmac;
                if ( pbkdf2params.prf.algorithm.equals(new OBJECTIDENTIFIER(HMAC.idhmacWithSHA256)) ) {
                    hmac = new HMAC(new SHA256());
                    hmac.init(((OCTETSTRING)pbkdf2params.prf.parameters).getValue());
                } else {
                    throw new UnsupportedOperationException();
                }
                Block block;
                if ( s.get(0,1,1,0).equals(AES.sub(42))) {
                    block = new CBC(new AES());
                } else {
                    throw new UnsupportedOperationException();
                }
                byte[] iv = ((OCTETSTRING)s.get(0,1,1,1)).getValue(); // iv か何か
                byte[] enc = ((OCTETSTRING)s.get(1)).getValue();
                
                kdf.init(new HMAC(new SHA256()), salt, c);
                es.init(block, hmac, pass, salt, c);
                byte[] dec = es.decrypt(enc);
                SEQUENCE seq = (SEQUENCE)ASN1Util.toASN1(dec);
                System.out.println(seq);
            }
        }
        throw new UnsupportedOperationException();
    }
    
}
