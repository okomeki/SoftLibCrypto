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

/**
 * SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions (FIPS PUB 202).
 * Secure Hash Algorithm-3 (SHA-3) family.
 * w=64 (long) で最適化したもの
 * SHA3-224, SHA3-256, SHA3-384, SHA3-512 に対応
 * little endian ?
 */
public class SHA3 extends Keccak {

    static final String nistAlgorithms = ".4";
    static final String hashAlgs = nistAlgorithms + ".2";

    /**
     * r は 1152,1088,832,576
     *
     * @param n 出力長 224,256,384,512
     */
    public SHA3(int n) {
        super("SHA3-", 2 * n, n, (byte) 0x06);
    }

}
