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
package net.siisise.ietf.pkcs5;

import java.util.LinkedHashMap;
import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.ASN1Object;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.security.digest.SHA1;
import net.siisise.security.mac.HMAC;

/**
 * RFC 8018 A.2. PBKDF2
 */
public class PBKDF2params {

    public ASN1Object salt; // CHOICE { OCTETSTRING , AlgorithmIdentifier }
    public INTEGER iterationCount;
    public INTEGER keyLength;
    public AlgorithmIdentifier prf;

    /**
     * 
     * @param s AlgorithmIdentifier params
     * @return 
     */
    public static PBKDF2params decode(SEQUENCE s) {
        PBKDF2params params = new PBKDF2params();
        params.salt = s.get(0); // choice specified OCTET STRING
        // otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
        params.iterationCount = (INTEGER) s.get(1);
        int offset = 2;
        if (s.get(2) instanceof INTEGER) {
            params.keyLength = (INTEGER) s.get(2); // OPTIONAL
            offset++;
        }
        if (s.size() >= offset) {
            params.prf = AlgorithmIdentifier.decode((SEQUENCE) s.get(offset++));
        } else {
            params.prf = new AlgorithmIdentifier(HMAC.idhmacWithSHA1);
        }
        return params;
    }

    public SEQUENCE encodeASN1() {
        return (SEQUENCE)rebind(new ASN1Convert());
/*
        SEQUENCE seq = new SEQUENCE();
        seq.add(salt);
        seq.add(iterationCount);
        if (keyLength != null) {
            seq.add(keyLength); // OPTIONAL
        }
        seq.add(prf.encodeASN1()); // DEFAULT algid-hmacWithSHA1
        return seq;
*/
    }

    /**
     * ASN.1 ベースの汎用出力.
     * @param <V>
     * @param format
     * @return 
     */
    public <V> V rebind(TypeFormat<V> format) {
        LinkedHashMap<String, Object> params = new LinkedHashMap<>();
        params.put("salt", salt); // specified OCTET STRING または otherSource AlgorithmIdentifier
        params.put("iterationCount", iterationCount);
        if (keyLength != null) { // OPTIONAL
            params.put("keyLength", keyLength);
        }
        params.put("prf", prf); // DEFAULT algid-hmacWithSHA1
        return Rebind.valueOf(params, format);
    }

    public PBKDF2 decode() {
        byte[] tsalt;
        if (this.salt instanceof OCTETSTRING) {
            tsalt = ((OCTETSTRING) salt).getValue();
        } else {
            AlgorithmIdentifier pbkdf2SaltSources = AlgorithmIdentifier.decode((SEQUENCE) salt);
            throw new UnsupportedOperationException();
        }
        int c = iterationCount.getValue().intValue();
        HMAC hprf;
        if (prf != null) {
            hprf = HMAC.decode(prf);
        } else {
            hprf = new HMAC(new SHA1());
        }
        PBKDF2 kdf = new PBKDF2(hprf);
        if (keyLength != null) {
            kdf.init(hprf, tsalt, c, keyLength.intValue());
        } else {
            kdf.init(hprf, tsalt, c);
        }
        return kdf;
    }
}
