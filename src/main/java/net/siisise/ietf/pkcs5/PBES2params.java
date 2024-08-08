/*
 * Copyright 2023-2024 okome.
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
package net.siisise.ietf.pkcs5;

import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;
import net.siisise.security.mode.CBC;
import net.siisise.security.mode.CCM;
import net.siisise.security.mode.CFB;
import net.siisise.security.mode.ECB;
import net.siisise.security.mode.GCM;
import net.siisise.security.mode.OFB;
import net.siisise.security.mode.PKCS7Padding;

/**
 * PKCS #5
 * RFC 8018 A.4. PBES2
 */
public class PBES2params {
    public AlgorithmIdentifier keyDerivationFunc;
    public AlgorithmIdentifier encryptionScheme;

    public PBES2params() {
        
    }

    /**
     * 
     * @param kp KDF OID と パラメータ (PBKDF2 固定)
     * @param eid 暗号OID
     * @param salt 
     */
    public PBES2params(PBKDF2params kp, OBJECTIDENTIFIER eid, byte[] salt) {
        keyDerivationFunc = new AlgorithmIdentifier(PBKDF2.OID, kp.encodeASN1());
        ASN1Tag opt;
        if ( salt == null ) {
            opt = new NULL();
        } else  {
            opt = new OCTETSTRING(salt);
        }
        encryptionScheme = new AlgorithmIdentifier(eid, opt );
    }
    
    public static PBES2params decode(SEQUENCE s) {
        PBES2params params = new PBES2params();
        params.keyDerivationFunc = AlgorithmIdentifier.decode((SEQUENCE) s.get(0));
        params.encryptionScheme = AlgorithmIdentifier.decode((SEQUENCE) s.get(1));
        return params;
    }
    
    public PBES2 decode() {
        PBES2 es;
        PBKDF2 kdf;
        if ( keyDerivationFunc.algorithm.equals(PBKDF2.OID)) {
            kdf = PBKDF2params.decode((SEQUENCE) keyDerivationFunc.parameters).decode();
            es = new PBES2(kdf);
        } else {
            throw new UnsupportedOperationException(keyDerivationFunc.algorithm.toString());
        }
        Block block = getEncryptionScheme(encryptionScheme.algorithm);
        if (encryptionScheme.parameters instanceof OCTETSTRING) {
            byte[] iv = ((OCTETSTRING)encryptionScheme.parameters).getValue();
            es.setParam(iv);
        }
        es.setBlock(block);
        return es;
    }
    
    public SEQUENCEMap encode() {
        SEQUENCEMap seq = new SEQUENCEMap();
        seq.put("keyDerivationFunc", keyDerivationFunc.encodeASN1());
        seq.put("encryptionScheme", encryptionScheme.encodeASN1());
        return seq;
    }

    /**
     * 仮
     */
    static final OBJECTIDENTIFIER AES = new OBJECTIDENTIFIER("2.16.840.1.101.3.4.1");
    static final OBJECTIDENTIFIER aes128_ECB_PAD = AES.sub(1);
    static final OBJECTIDENTIFIER aes128_CBC_PAD = AES.sub(2);
    static final OBJECTIDENTIFIER aes128_OFB = AES.sub(3);
    static final OBJECTIDENTIFIER aes128_CFB = AES.sub(4);
    static final OBJECTIDENTIFIER aes128_GCM = AES.sub(6);
    static final OBJECTIDENTIFIER aes128_CCM = AES.sub(7);
    static final OBJECTIDENTIFIER aes192_ECB_PAD = AES.sub(21);
    static final OBJECTIDENTIFIER aes192_CBC_PAD = AES.sub(22);
    static final OBJECTIDENTIFIER aes192_OFB = AES.sub(23);
    static final OBJECTIDENTIFIER aes192_CFB = AES.sub(24);
    static final OBJECTIDENTIFIER aes192_GCM = AES.sub(26);
    static final OBJECTIDENTIFIER aes192_CCM = AES.sub(27);
    static final OBJECTIDENTIFIER aes256_ECB_PAD = AES.sub(41);
    public static final OBJECTIDENTIFIER aes256_CBC_PAD = AES.sub(42);
    static final OBJECTIDENTIFIER aes256_OFB = AES.sub(43);
    static final OBJECTIDENTIFIER aes256_CFB = AES.sub(44);
    static final OBJECTIDENTIFIER aes256_GCM = AES.sub(46);
    static final OBJECTIDENTIFIER aes256_CCM = AES.sub(47);
    
    /**
     * RFC 2898 ?.
     * Stream モードがないものにはPKCS7Padding をつける?
     * @param alg アルゴリズム OID
     * @return Block暗号 (仮)
     */
    public static Block getEncryptionScheme(OBJECTIDENTIFIER alg) {
        // どこか
        if (alg.up().equals(AES)) {
            if ( aes128_ECB_PAD.equals(alg) ) {
                return new PKCS7Padding(new ECB(new AES()));
            } else if ( aes128_CBC_PAD.equals(alg) ) {
                return new PKCS7Padding(new CBC(new AES()));
            } else if ( aes128_OFB.equals(alg) ) {
                return new OFB(new AES());
            } else if ( aes128_CFB.equals(alg) ) {
                return new CFB(new AES());
            } else if ( aes128_GCM.equals(alg) ) {
                return new GCM(new AES());
            } else if ( aes128_CCM.equals(alg) ) {
                return new CCM(new AES());
            } else if ( aes192_ECB_PAD.equals(alg) ) {
                return new PKCS7Padding(new ECB(new AES(192)));
            } else if ( aes192_CBC_PAD.equals(alg) ) {
                return new PKCS7Padding(new CBC(new AES(192)));
            } else if ( aes192_OFB.equals(alg) ) {
                return new OFB(new AES(192));
            } else if ( aes192_CFB.equals(alg) ) {
                return new CFB(new AES(192));
            } else if ( aes192_GCM.equals(alg) ) {
                return new GCM(new AES(192));
            } else if ( aes192_CCM.equals(alg) ) {
                return new CCM(new AES(192));
            } else if ( aes256_ECB_PAD.equals(alg) ) {
                return new PKCS7Padding(new ECB(new AES(256)));
            } else if ( aes256_CBC_PAD.equals(alg) ) {
                return new PKCS7Padding(new CBC(new AES(256)));
            } else if ( aes256_OFB.equals(alg) ) {
                return new OFB(new AES(256));
            } else if ( aes256_CFB.equals(alg) ) {
                return new CFB(new AES(256));
            } else if ( aes256_GCM.equals(alg) ) {
                return new GCM(new AES(256));
            } else if ( aes256_CCM.equals(alg) ) {
                return new CCM(new AES(256));
            }
        }
        // B.2.2. DES-EDE3-CBC-Pad
        // RFC 1423 Padding
        //       24 octet encryption keey
        // param CBC 8 byte ぐらい initialization vector
        
        // B.2.3. RC2-CBC-Pad
        // RFC 2268
        // param 1-128 octet 鍵
        //       1-1024 bit effective key bits
        //       8 octet initicalization vector
        
        throw new UnsupportedOperationException("encryptionScheme:" + alg.toString());
    }
}
