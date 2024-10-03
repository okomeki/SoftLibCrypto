/*
 * Copyright 2023 Siisise Net.
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
 * FIPS PUB 202
 * Secure Hash Algorithm KECCAK 256
 * 6.2 SHA-3 Extendable-Output Functions
 * 拡張出力関数 XOF
 * NIST SP 800-185
 */
public class SHAKE256 extends SHAKE {

    /**
     * 512bit 固定長OID.
     * RFC 8702 id-shake256
     */
    static final OBJECTIDENTIFIER OID = SHA3.hashAlgs.sub(12);

    /**
     * 可変長OID.
     * RFC 8702 draft 07まで
     * 
     * https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration
     * パラメータ
     * ShakeOutputLen :== INTEGER -- Output length in bits
     */
    static final OBJECTIDENTIFIER OIDlen = SHA3.hashAlgs.sub(18);

    public SHAKE256(int d) {
        super(256, d);
    }
    
    /**
     * X.509, CMSで利用される初期値512で利用する.
     */
    public SHAKE256() {
        this(512);
    }

}
