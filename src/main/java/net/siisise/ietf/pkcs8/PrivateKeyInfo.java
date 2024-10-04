/*
 * Copyright 2024 okome.
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

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.ietf.pkcs.asn1.PrivateKeyAlgorithmIdentifier;
import net.siisise.iso.asn1.ASN1Cls;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEList;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * PKCS #8 PrivateKeyInfo.
 * RFC 5208 PKCS #8 5. Private-Key Information Syntax
 * RFC 5958
 */
public class PrivateKeyInfo {
//    static class Version extends INTEGER {}

    public static class PrivateKey extends OCTETSTRING {
        public PrivateKey() {
        }
        public PrivateKey(byte[] key) {
            super(key);
        }
    }
//    static class Attributes extends SEQUENCEList {}
    
    public int version;
    AlgorithmIdentifier privateKeyAlgorithm;
    byte[] privateKey;
    List attributes; // [0]
    
    public PrivateKeyInfo() {
    }
    
    public PrivateKeyInfo(OBJECTIDENTIFIER oid, byte[] privateKey) {
        version = 0;
        privateKeyAlgorithm = new PrivateKeyAlgorithmIdentifier(oid);
        this.privateKey = privateKey;
    }
    
    public <T> T rebind(TypeFormat<T> format) {
        LinkedHashMap s = new LinkedHashMap();
        s.put("version", version);
        s.put("privateKeyAlgorithm", privateKeyAlgorithm);
        s.put("privateKey", privateKey);
        if (attributes != null) {
            SEQUENCEList atrs = new SEQUENCEList(ASN1Cls.CONTEXT_SPECIFIC, 0);
            atrs.add((ASN1Tag)Rebind.valueOf(attributes, ASN1Tag.class));
            s.put("attributes", atrs);
        }
        return Rebind.valueOf(s,format);
    }
    
    public SEQUENCEMap encodeASN1() {
        SEQUENCEMap s = new SEQUENCEMap();
        s.put("version", new INTEGER(version));
        s.put("privateKeyAlgorithm", privateKeyAlgorithm.encodeASN1());
        s.put("privateKey", new OCTETSTRING(privateKey));
        if ( attributes != null ) {
            SEQUENCEList atrs = new SEQUENCEList(ASN1Cls.CONTEXT_SPECIFIC, 0);
            s.put("attributes", atrs);
        }
        return s;
    }

    public static PrivateKeyInfo decode(SEQUENCE seq) {
        INTEGER ver = (INTEGER) seq.get(0);
        if ( ver.getValue().equals(BigInteger.ZERO)) {
            AlgorithmIdentifier ai = AlgorithmIdentifier.decode((SEQUENCE) seq.get(1));
            if (ai.parameters.equals(new NULL()) ) {
                PrivateKeyInfo info = new PrivateKeyInfo(ai.algorithm, ((OCTETSTRING)seq.get(2)).getValue());
                if (seq.size() == 3) {
                    return info;
                }
            }
        }
        throw new UnsupportedOperationException();
    }
}
