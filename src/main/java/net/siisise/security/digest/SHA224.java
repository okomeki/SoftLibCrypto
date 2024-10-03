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
 * SHA-224.
 * FIPS PUB 180-2
 * RFC 3874
 */
public class SHA224 extends SHA256 {

    public static final OBJECTIDENTIFIER OID = SHA256.hashAlgs.sub(4);

    static int[] IV224 = {
        0xc1059ed8,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4
    };
    
    public SHA224() {
        super("SHA-224", IV224);
    }
    
    @Override
    protected int engineGetDigestLength() {
        return 28;
    }

}
