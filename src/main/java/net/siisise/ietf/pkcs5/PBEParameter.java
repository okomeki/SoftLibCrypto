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

import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;

/**
 * PBES1用
 */
public class PBEParameter {
    byte[] salt;
    int iterationCount;

    public SEQUENCE encodeASN1() {
        SEQUENCE s = new SEQUENCE();
        s.add(new OCTETSTRING(salt));
        s.add(iterationCount);
        return s;
    }
    
    public PBES1 encode(OBJECTIDENTIFIER oid, byte[] password) {
        PBES1 es = new PBES1();
        es.init(oid, password, salt, iterationCount);
        return es;
    }
}
