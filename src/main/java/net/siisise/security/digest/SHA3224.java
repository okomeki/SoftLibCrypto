/*
 * Copyright 2021 Siisise Net.
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
package net.siisise.security.digest;

import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;

/**
 * SHA3-224
 */
public class SHA3224 extends SHA3 {
    
    static final OBJECTIDENTIFIER OID = hashAlgs.sub(7);
    
    public SHA3224() {
        super(224);
    }
}
