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

/**
 * FIPS PUB 202
 * Secure Hash Algorithm KECCAK 128
 * 6.2 SHA-3 Extendable-Output Functions
 * 拡張出力関数 XOF
 * SHAKE128
 */
public class SHAKE128 extends SHAKE {
    
    static final String OID = SHA3.hashAlgs + ".11";
    static final String OIDlen = SHA3.hashAlgs + ".17";

    /**
     * 
     * @param d ビット数
     */
    public SHAKE128(int d) {
        // M || 1111
        super(128,d);
    }

}
