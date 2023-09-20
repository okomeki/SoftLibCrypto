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

import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.block.Block;

/**
 * 
 */
public class EncryptionSchemes {
    
    /**
     * RFC 8018 B.2. Encryption Schemes
     * PBES2 [RFC 2898]
     *   AES-CBC-Pad
     *   RC5-CBC-Pad
     *   旧
     *   DES-CBC-Pad RFC 1423
     *   DES-EDE3-CBC-Pad
     *   RC2-CBC-Pad
     * 
     * @param oid
     * @return 
     */
    static Block decode(OBJECTIDENTIFIER oid) {
        throw new UnsupportedOperationException();
    }
    
}
