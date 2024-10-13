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
import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.ASN1Prefixed;
import net.siisise.iso.asn1.tag.BITSTRING;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 5958 OneAsymmetricKey [v2].
 * OneAsymmetricKey ::= SEQUENCE {
 *   version Version,
 *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *   privateKey PrivateKey,
 *   attributes [0] Attributes OPTIONAL,
 *   ...,
 *   [[2: publicKey [1] PublicKey OPTIONAL ]],
 *   ... }
 *
 * v1相当 RFC 5208
 * PrivateKeyInfo ::= SEQUENCE {
 *   version Version,
 *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *   privateKey PrivateKey,
 *   attributes [0] IMPLICIT Attributes OPTIONAL } }
 *
 *
 * RFC 5208 PrivateKeyInfo [v1]
 */
public class OneAsymmetricKey extends PrivateKeyInfo {
    
    public static final OBJECTIDENTIFIER id_ct_KP_aKeyPackage = new OBJECTIDENTIFIER("2.16.840.1.101.2.1.2.78.5");

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
    
    public OneAsymmetricKey() {
    }
    
    /**
     * 
     * @param oid Object Identifier
     * @param privateKey 秘密鍵
     */
    public OneAsymmetricKey(OBJECTIDENTIFIER oid, byte[] privateKey) {
        super(oid, privateKey);
    }
    
    public OneAsymmetricKey(AlgorithmIdentifier ai, byte[] privateKey) {
        super(ai, privateKey);
    }

//    public OBJECTIDENTIFIER privateKeyAlgorithm;
//    public OCTETSTRING privateKey;
//    public List attributes; // [0] Attributes OPTIONAL
    public BITSTRING publicKey; // [1] PublicKey OPTIONAL

    @Override
    public SEQUENCEMap encodeASN1() {
        SEQUENCEMap one = new SEQUENCEMap();
        one.put("version", version);
        one.put("privateKeyAlgorithm", privateKeyAlgorithm.encodeASN1());
        one.put("privateKey", privateKey);
        if ( attributes != null ) {
            //ASN1Prefixed pre0 = new ASN1Prefixed(0, Rebind.valueOf(attributes, new ASN1Convert()));
            SEQUENCE pre0 = (SEQUENCE) Rebind.valueOf(attributes, new ASN1Convert());
            pre0.setContextSpecific(0);
            one.put("attributes", pre0);
        }
        if (publicKey != null && version > 0) {
            ASN1Prefixed pre1 = new ASN1Prefixed(1, publicKey);
            one.put("publicKey", pre1);
        }
        return one;
    }

    /**
     *
     * @param <V>
     * @param format
     * @return
     */
    @Override
    public <V> V rebind(TypeFormat<V> format) {
        LinkedHashMap map = new LinkedHashMap();
        map.put("version", version);
        map.put("privateKeyAlgorithm", privateKeyAlgorithm);
        map.put("privateKey", privateKey);

        if (attributes != null) {
            ASN1Prefixed pre1 = new ASN1Prefixed(1, Rebind.valueOf(attributes, new ASN1Convert()));
            map.put("attributes", pre1);
        }

        if (publicKey != null && version >= 1) {
            ASN1Prefixed pre1 = new ASN1Prefixed(1, publicKey);
            map.put("publicKey", pre1);
        }
        return format.mapFormat(map); //Rebind.valueOf(map, format);
    }

    /**
     * ToDo: overflow
     * @param s
     * @return 
     */
    public static PrivateKeyInfo decode(SEQUENCE s) {
        INTEGER ver = (INTEGER)s.get(0);
        long longVer = ver.longValue();
        if ( longVer == 1 ) {
            OneAsymmetricKey key = new OneAsymmetricKey();
            key.version = ver.intValueExact();
            key.privateKeyAlgorithm = AlgorithmIdentifier.decode( (SEQUENCE) s.get(1));
            key.privateKey = ((OCTETSTRING) s.get(2)).getValue();
            key.publicKey = (BITSTRING) s.getContextSpecific(0);
            return key;
        } else {
            return PrivateKeyInfo.decode(s);
        }
    }
}
