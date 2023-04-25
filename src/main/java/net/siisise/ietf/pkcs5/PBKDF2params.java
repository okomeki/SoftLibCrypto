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

import net.siisise.iso.asn1.ASN1Object;
import net.siisise.ietf.pkcs1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;

/**
 * RFC 8018 A.2. PBKDF2
 */
public class PBKDF2params {
    public ASN1Object salt;
    public INTEGER iterationCount;
    public INTEGER keyLength;
    public AlgorithmIdentifier prf;
    public OBJECTIDENTIFIER algid;
    
    public static PBKDF2params decode(SEQUENCE s) {
        PBKDF2params params = new PBKDF2params();
        params.salt = s.get(0); // choice specified OCTET STRING
                         // otherSource AlgorithmIdentifier {{PBKDF2-SaltSources}}
        params.iterationCount = (INTEGER) s.get(1);
        if (s.get(2) instanceof INTEGER) {
            params.keyLength = (INTEGER) s.get(2); // OPTIONAL
        }
        params.prf = AlgorithmIdentifier.decode((SEQUENCE) s.get(3));
        params.algid = (OBJECTIDENTIFIER)s.get(4);
        return params;
    }
}
