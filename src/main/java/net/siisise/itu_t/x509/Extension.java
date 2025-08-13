/*
 * Copyright 2025 okome.
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
package net.siisise.itu_t.x509;

import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.tag.BOOLEAN;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 5280 4.1. Extension
 * 4.1.2.9. Extensions
 * 4.2. Certificate Extensions
 * 
 */
public class Extension {
    public OBJECTIDENTIFIER extnID;
    /**
     * critical BOOLEAN DEFAULT FALSE.
     * false　のときは省略かも
     */
    public boolean critical = false;
    public byte[] extnValue;
    
    public <T> T rebind(TypeFormat<T> format) {
        SEQUENCEMap ex = new SEQUENCEMap<>();
        ex.put("extnID", extnID);
        if (critical != false) {
            ex.put("critical", new BOOLEAN(critical));
        }
        ex.put("extnValue", new OCTETSTRING(extnValue));
        return (T)ex.rebind(format);
    }
}
