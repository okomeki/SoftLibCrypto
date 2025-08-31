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

import java.math.BigInteger;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.security.mac.HMAC;

/**
 * RFC 8018 A.2. PBKDF2
 * 
 * PBKDF2-params ::= SEQUENCE {
 *     salt CHOICE {
 *         specified OCTET STRING,
 *         otherSource AlgorithmIdentifier {{PBKDF2-SaltSource}}
 *     },
 *     iterationCount INTEGER (1..MAX),
 *     keyLength INTEGER (1..MAX) OPTIONAL,
 *     prf AlgorithmIdentifier {{PBKDF2-PRFs}} DEFAULT
 *     algid-hmacWithSHA1 }
 * {
 */
public class PBKDF2params {

    public ASN1Tag salt; // CHOICE { OCTETSTRING , AlgorithmIdentifier }
    public BigInteger iterationCount;
    public BigInteger keyLength;
    public AlgorithmIdentifier prf = new AlgorithmIdentifier(HMAC.idhmacWithSHA1);

    public PBKDF2params(byte[] salt, long iterationCount, int keyLength) {
        this.salt = new OCTETSTRING(salt);
        this.iterationCount = BigInteger.valueOf(iterationCount);
        this.keyLength = BigInteger.valueOf(keyLength);
    }
    
    public PBKDF2params(byte[] salt, long iterationCount) {
        this.salt = new OCTETSTRING(salt);
        this.iterationCount = BigInteger.valueOf(iterationCount);
    }

    /**
     * PBKDF2パラメータ
     * @param salt 塩
     * @param iterationCount ストレッチ数 繰り返し
     * @param prfOID HMAC OID
     */
    public PBKDF2params(byte[] salt, long iterationCount, OBJECTIDENTIFIER prfOID) {
        this.salt = new OCTETSTRING(salt);
        this.iterationCount = BigInteger.valueOf(iterationCount);
        if (prfOID != null) {
            prf = new AlgorithmIdentifier(prfOID);
        }
    }

    PBKDF2params() {
    }
    
    /**
     * ASN.1 AlgorithmIdentifier からパラメータを読み込む.
     * @param s AlgorithmIdentifier params
     * @return パラメータ
     */
    public static PBKDF2params decode(SEQUENCE s) {
        PBKDF2params params = new PBKDF2params();
        params.salt = s.get(0); // choice specified OCTET STRING
        // otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
        params.iterationCount = ((INTEGER) s.get(1)).getValue();
        int offset = 2;
        if (s.get(2) instanceof INTEGER) {
            params.keyLength = ((INTEGER) s.get(2)).getValue(); // OPTIONAL
            offset++;
        }
        if (s.size() >= offset) {
            params.prf = AlgorithmIdentifier.decode((SEQUENCE) s.get(offset++));
        } else {
            params.prf = new AlgorithmIdentifier(HMAC.idhmacWithSHA1);
        }
        return params;
    }

    public SEQUENCEMap encodeASN1() {
//        return (SEQUENCE)rebind(new ASN1Convert());

        SEQUENCEMap params = new SEQUENCEMap();
        params.put("salt", salt); // specified OCTET STRING または otherSource AlgorithmIdentifier
        params.put("iterationCount", iterationCount);
        if (keyLength != null) {
            params.put("keyLength", keyLength); // OPTIONAL
        }
        params.put("prf", prf); // DEFAULT algid-hmacWithSHA1
        return params;
    }

    /**
     * ASN.1 ベースの汎用出力.
     * @param <V> DER や ASN1Object
     * @param format 適度な型
     * @return ASN.1っぽいPBKDF2 のパラメータ
     */
    public <V> V rebind(TypeFormat<V> format) {
        SEQUENCEMap params = new SEQUENCEMap();
        params.put("salt", salt); // specified OCTET STRING または otherSource AlgorithmIdentifier
        params.put("iterationCount", iterationCount);
        if (keyLength != null) { // OPTIONAL
            params.put("keyLength", keyLength);
        }
        params.put("prf", prf); // DEFAULT algid-hmacWithSHA1
        return (V)params.rebind(format);
    }

    /**
     * パラメータを引き渡してPBKDF2を生成する.
     * @return PBKDF2
     */
    public PBKDF2 decode() {
        byte[] tsalt;
        if (this.salt instanceof OCTETSTRING) {
            tsalt = ((OCTETSTRING) salt).getValue();
        } else {
            AlgorithmIdentifier pbkdf2SaltSources = AlgorithmIdentifier.decode((SEQUENCE) salt);
            throw new UnsupportedOperationException();
        }
        int c = iterationCount.intValueExact(); // 仮int
        PBKDF2 kdf;
        if (prf != null) {
            HMAC hprf = HMAC.decode(prf);
            kdf = new PBKDF2(hprf);
        } else {
            kdf = new PBKDF2();
        }
        if (keyLength != null) {
            kdf.init(tsalt, c, keyLength.intValueExact());
        } else {
            kdf.init(tsalt, c);
        }
        return kdf;
    }

    /**
     * AES-CBC-Pad ぐらいの
     * @return 簡単生成パラメータ
     */
    public PBKDF2params gen() {
        PBKDF2params kdf2p = new PBKDF2params();
        kdf2p.iterationCount = BigInteger.valueOf(2048);
        return kdf2p;
    }
}
