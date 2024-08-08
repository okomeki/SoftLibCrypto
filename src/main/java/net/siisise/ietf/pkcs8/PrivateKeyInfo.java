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

import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEList;

/**
 * RFC 5208 PKCS #8 5. Private-Key Information Syntax
 */
public class PrivateKeyInfo {
    static class Version extends INTEGER {}

    public static class PrivateKey extends OCTETSTRING {
        public PrivateKey() {
        }
        public PrivateKey(byte[] key) {
            super(key);
        }
    }
    static class Attributes extends SEQUENCEList {}
    
    public INTEGER version;
    AlgorithmIdentifier privateKeyAlgorithm;
    OCTETSTRING privateKey;
    SEQUENCE attributes; // [0]
    
    
}
