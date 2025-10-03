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

import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * PBES1用
 */
public class PBEParameter {

    public byte[] salt;
    int iterationCount;

    public PBES1 encode(OBJECTIDENTIFIER oid, byte[] password) {
        PBES1 es = decode();
        es.init(oid, password);
        return es;
    }

    public PBES1 decode() {
        PBES1 es = new PBES1();
        es.init(salt, iterationCount);
        return es;
    }
    
    public static PBEParameter decode(SEQUENCE ps) {
        PBEParameter pbe = new PBEParameter();
        pbe.salt = ((OCTETSTRING) ps.get("salt", 0)).getValue();
        pbe.iterationCount = ((INTEGER)ps.get("iterationCount", 1)).intValue();
        return pbe;
    }
    
    public static PBES1 decode(AlgorithmIdentifier ai) {
        PBEParameter pbe = decode((SEQUENCE)ai.parameters);
        PBES1 es = pbe.decode();
        es.init(ai.algorithm);
        return es;
    }
    
    public <V> V rebind(TypeFormat<V> format) {
        SEQUENCEMap seq = new SEQUENCEMap();
        seq.put("salt", new OCTETSTRING(salt));
        seq.put("iterationCount", new INTEGER(iterationCount));
        return Rebind.valueOf(seq, format);
    }
}
