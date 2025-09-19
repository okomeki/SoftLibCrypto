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
package net.siisise.security.key;

import java.math.BigInteger;
import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.tag.BITSTRING;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 3279 2.3.3 Diffie-Hellman Key Exchange Keys
 */
public class DHDomainParameters {
    
    public static class ValidationParams {
        public byte[] seed;
        public BigInteger pgenCounter;
        
        public <T> T rebind(TypeFormat<T> format) {
            SEQUENCEMap validation = new SEQUENCEMap();
            validation.put("seed", new BITSTRING(seed));
            validation.put("pgenCounter", pgenCounter);
            return (T) validation.rebind(format);
        }
    }

    /**
     * ガロアのp
     */
    BigInteger p;
    BigInteger g;
    BigInteger q;
    BigInteger j;
    ValidationParams validationParams;
    
    public <T> T rebind(TypeFormat<T> format) {
        SEQUENCEMap params = new SEQUENCEMap();
        params.put("p",p);
        params.put("g",g);
        params.put("q",q);
        if (j != null) {
            params.put("j",j);
        }
        if (validationParams != null) {
            params.put("validationParams", validationParams.rebind(format));
        }
        return (T) params.rebind(format);
    }
    
}
