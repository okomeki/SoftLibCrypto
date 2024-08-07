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
package net.siisise.ietf.pkcs.asn1;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.ASN1Cls;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCEList;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 5208 Section 5. Private-Key Information Syntax
 * PKCS #8
 */
public class PrivateKeyInfo {

    public int version;
    public PrivateKeyAlgorithmIdentifier privateKeyAlgorithm;
    public byte[] privateKey;
    public List attributes;

    /**
     * AlgorithmIdentifier (パラメータはNULL) と privateKey を設定する
     * @param oid AlgorithmIdentifier のalgorithm
     * @param privateKey 秘密鍵のASN.1 DER
     */
    public PrivateKeyInfo(OBJECTIDENTIFIER oid, byte[] privateKey) {
        version = 0;
        privateKeyAlgorithm = new PrivateKeyAlgorithmIdentifier(oid);
        this.privateKey = privateKey;
    }

    public PrivateKeyInfo(String oid, byte[] privateKey) {
        version = 0;
        privateKeyAlgorithm = new PrivateKeyAlgorithmIdentifier(oid);
        this.privateKey = privateKey;
    }

    public <T> T rebind(TypeFormat<T> format) {
        LinkedHashMap s = new LinkedHashMap();
        s.put("version", version);
        s.put("privateKeyAlgorithm", privateKeyAlgorithm);
        s.put("privateKey", privateKey);
        return Rebind.valueOf(s,format);
    }

    public SEQUENCEMap encodeASN1() {
        SEQUENCEMap s = new SEQUENCEMap();
        s.put("version", new INTEGER(version));
        s.put("privateKeyAlgorithm", privateKeyAlgorithm.encodeASN1());
        s.put("privateKey", new OCTETSTRING(privateKey));
        if ( attributes != null ) {
            SEQUENCEList atrs = new SEQUENCEList(ASN1Cls.CONTEXT_SPECIFIC, 0);
            //for ( a : attributes) {
                
            //}
            s.put("attributes", atrs);
            // attributes [0] IMPLICIT Attributes OPTIONAL
            throw new UnsupportedOperationException();
        }
        return s;
    }

    public static PrivateKeyInfo decode(SEQUENCEList seq) {
        INTEGER ver = (INTEGER) seq.get(0);
        if ( ver.getValue().equals(BigInteger.ZERO)) {
            AlgorithmIdentifier ai = AlgorithmIdentifier.decode((SEQUENCEList) seq.get(1));
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
