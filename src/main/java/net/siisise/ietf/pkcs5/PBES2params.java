/*
 * Copyright 2023-2025 okome.
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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.LinkedHashMap;
import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;
import net.siisise.security.block.DES;
import net.siisise.security.block.RC2;
import net.siisise.security.block.TripleDES;
import net.siisise.security.mac.HMAC;
import net.siisise.security.mode.CBC;
import net.siisise.security.mode.PKCS7Padding;

/**
 * PKCS #5
 * RFC 8018 A.4. PBES2
 * 暗号利用モード CBC-PADが標準の対応 CFB,OFBも可。
 * OpenSSL PKCS #8ではECBでも使えるがCTR, AEAD(GCM)などは使えなかった。
 * ECBの符号化にも仮対応しておく。
 */
public class PBES2params {
    public AlgorithmIdentifier keyDerivationFunc; // PBKDF2 OID + PBKDF2params
    public AlgorithmIdentifier encryptionScheme;

    public PBES2params() {
        
    }

    /**
     * 
     * @param kp KDF OID と パラメータ (PBKDF2 固定)
     * @param eid 暗号OID
     * @param salt block暗号のivになるかもしれない
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

    /**
     * ASN.1から復元.
     * @param s ASN.1 PBES2params SEQUENCE
     * @return 復元 PBES2Params
     */
    public static PBES2params decode(SEQUENCE s) {
        PBES2params params = new PBES2params();
        params.keyDerivationFunc = AlgorithmIdentifier.decode((SEQUENCE) s.get(0));
        params.encryptionScheme = AlgorithmIdentifier.decode((SEQUENCE) s.get(1));
        return params;
    }

    /**
     * KDF と 暗号から
     * 暗号は IV などをパラメータとして持っているので初期化時に共通鍵以外を設定済みにしておける。
     * 暗号化モードの設定による。
     * @return 復元されたPBES2
     */
    public PBES2 decode() {
        PBES2 es;
        // keyDerivationFunc
        // RFC 8018 では PBKDF2 のみ
        if ( keyDerivationFunc.algorithm.equals(PBKDF2.OID)) {
            PBKDF2 kdf = PBKDF2params.decode((SEQUENCE) keyDerivationFunc.parameters).decode();
            es = new PBES2(kdf);
        } else {
            throw new UnsupportedOperationException(keyDerivationFunc.algorithm.toString());
        }
        // encryptionScheme
        Block block = getEncryptionScheme(encryptionScheme.algorithm);
        if (encryptionScheme.parameters instanceof OCTETSTRING) {
            byte[] iv = ((OCTETSTRING)encryptionScheme.parameters).getValue(); // 仕様では salt 実質 IV
            if (iv.length > 0) { // CBC, CFB, OFB対応 ECBモードのsaltの長さ0　CTR AEAD(GCM) 未サポート
                es.setParam(iv);
            }
        } else {
            throw new UnsupportedOperationException("省略形は?");
        }
        es.setBlock(block);
        return es;
    }
    
    public SEQUENCEMap encode() {
        return (SEQUENCEMap)rebind(new ASN1Convert());
    }

    /**
     * ASN.1にあわせた出力.
     * @param <T> SEQUENCEMap 系の想定.
     * @param format ASN1Convert または ASN1DERFormat など
     * @return format にあわせた出力
     */
    public <T> T rebind(TypeFormat<T> format) {
        LinkedHashMap seq = new LinkedHashMap();
        seq.put("keyDerivationFunc", keyDerivationFunc);
        seq.put("encryptionScheme", encryptionScheme);
        return Rebind.valueOf(seq, format);
    }

//    static final OBJECTIDENTIFIER pkcs = PBKDF2.rsadsi.sub(1);
//    static final OBJECTIDENTIFIER pkcs_5 = pkcs.sub(5);
//    static final OBJECTIDENTIFIER digestAlgorithm = PBKDF2.rsadsi.sub(2);
//    static final OBJECTIDENTIFIER encryptionAlgorithm = PBKDF2.rsadsi.sub(3);

    /**
     * RFC 2898 ?.
     * Stream モードがないものにはPKCS7Padding をつける?
     * @param alg アルゴリズム OID
     * @return Block暗号 (仮)
     */
    public static Block getEncryptionScheme(OBJECTIDENTIFIER alg) {
        // どこか
        if (alg.up().equals(AES.AES)) {
            Block b = AES.toBlockPad(alg);
            if ( b != null ) {
                return b;
            }
        } else if (DES.desCBC.equals(alg)) { // des_CBC_PAD
            return new PKCS7Padding(new CBC(new DES()));
        } else if (TripleDES.desEDE3_CBC.equals(alg)) {
            return new PKCS7Padding(new CBC(new TripleDES()));
        } else if (RC2.rc2CBC.equals(alg)) {
            return new PKCS7Padding(new CBC(new RC2()));
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
    
    /**
     * AES-CBC 仮パラメータ生成.
     * OpenSSL と近くしておく
     * @return 仮パラメータ
     */
    public static PBES2params gen() {
        CBC cbc = new CBC(new AES());
        int[] pls = cbc.getParamLength();
        SecureRandom srnd;
        try {
            srnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
        byte[] salt = new byte[pls[1]/8]; // OpenSSL では 64bitかもしれない
        srnd.nextBytes(salt);
        PBKDF2params kdf2p = new PBKDF2params(salt,2048, HMAC.idhmacWithSHA256);
        salt = new byte[pls[0]/8];
        srnd.nextBytes(salt);
        return new PBES2params(kdf2p, AES.AES128_CBC_PAD, salt);
    }
}
