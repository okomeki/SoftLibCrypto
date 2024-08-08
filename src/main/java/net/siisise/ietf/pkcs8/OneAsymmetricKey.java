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

import java.util.LinkedHashMap;
import java.util.List;
import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.ASN1Cls;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.ASN1Prefixed;
import net.siisise.iso.asn1.tag.BITSTRING;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEList;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 5958 OneAsymmetricKey [v2] OneAsymmetricKey ::= SEQUENCE { version
 * Version, privateKeyAlgorithm PrivateKeyAlgorithmIdentifier, privateKey
 * PrivateKey, attributes [0] Attributes OPTIONAL, ..., [[2: publicKey [1]
 * PublicKey OPTIONAL ]], ... }
 *
 * v1相当 RFC 5208 PrivateKeyInfo ::= SEQUENCE { version Version,
 * privateKeyAlgorithm PrivateKeyAlgorithmIdentifier, privateKey PrivateKey,
 * attributes [0] IMPLICIT Attributes OPTIONAL } }
 *
 *
 * RFC 5208 PrivateKeyInfo [v1]
 */
public class OneAsymmetricKey extends PrivateKeyInfo {

    static enum Version {
        v1(0),
        v2(1);
        INTEGER n;

        Version(int n) {
            this.n = new INTEGER(n);
        }

        INTEGER value() {
            return n;
        }
    }

//    public OBJECTIDENTIFIER privateKeyAlgorithm;
//    public OCTETSTRING privateKey;
    public List attributes; // [0] Attributes OPTIONAL
    public BITSTRING publicKey; // [1] PublicKey OPTIONAL

    public SEQUENCEMap encodeASN1() {
        SEQUENCEMap one = new SEQUENCEMap();
        one.put("version", version);
        one.put("privateKeyAlgorithm", privateKeyAlgorithm.encodeASN1());
        one.put("privateKey", privateKey);
        if ( attributes != null ) {
            SEQUENCEList attrs = new SEQUENCEList(ASN1Cls.CONTEXT_SPECIFIC, 1);
            ASN1Prefixed pre1 = new ASN1Prefixed(1, Rebind.valueOf(attributes, new ASN1Convert()));
        }
        return one;
    }

    /**
     *
     * @param <V>
     * @param format
     * @return
     */
    public <V> V rebind(TypeFormat<V> format) {
        LinkedHashMap map = new LinkedHashMap();
        map.put("version", version);
        map.put("privateKeyAlgorithm", privateKeyAlgorithm);
        map.put("privateKey", privateKey);

        if (attributes != null) {
            ASN1Prefixed pre1 = new ASN1Prefixed(1, Rebind.valueOf(attributes, new ASN1Convert()));
            map.put("attributes", pre1);
        }

        if (publicKey != null && version.equals(Version.v2.value())) {
            map.put("publicKey", publicKey);
        }
        return Rebind.valueOf(map, format);
    }

    
    public static OneAsymmetricKey decodeASN1(SEQUENCE s) {
        OneAsymmetricKey key = new OneAsymmetricKey();
        key.version = (INTEGER) s.get(0);
        key.privateKeyAlgorithm = AlgorithmIdentifier.decode( (SEQUENCE) s.get(1));
        key.privateKey = (OCTETSTRING) s.get(2);

        return key;
    }
}
