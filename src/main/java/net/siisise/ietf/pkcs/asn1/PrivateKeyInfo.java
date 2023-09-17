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

import java.util.List;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;

/**
 * RFC 5208 Section 5. Private-Key Information Syntax
 * PKCS #8
 */
public class PrivateKeyInfo {
    public int version;
    public PrivateKeyAlgorithmIdentifier privateKeyAlgorithm;
    public byte[] privateKey;
    public List attributes;
    
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
    
    public SEQUENCE encodeASN1() {
        SEQUENCE s = new SEQUENCE();
        s.add(version);
        s.add(privateKeyAlgorithm.encodeASN1());
        s.add(new OCTETSTRING(privateKey));
        if ( attributes != null ) {
            // attributes [0] IMPLICIT Attributes OPTIONAL
            throw new UnsupportedOperationException();
        }
        return s;
    }
}
