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

import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;

/**
 *
 */
public class OneAsymmetricKey {
    int version; // v1(0) RFC 5208 v2(1) RFC 5958
    OBJECTIDENTIFIER privateKeyAlgorithm;
    OCTETSTRING privateKey;

    public SEQUENCE encodeASN1() {
        SEQUENCE one = new SEQUENCE();
        one.add(new INTEGER(version));
        one.add(privateKeyAlgorithm);
        one.add(privateKey);
        return one;
    }
    
    public static OneAsymmetricKey decodeASN1(SEQUENCE s) {
        OneAsymmetricKey key = new OneAsymmetricKey();
        key.version = ((INTEGER)s.get(0)).getValue().intValue();
        key.privateKeyAlgorithm = (OBJECTIDENTIFIER) s.get(1);
        key.privateKey = (OCTETSTRING) s.get(2);
        return key;
    }
}
