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
 * RawSHAKE128(J,d) = KECCAK[256](J||11,d)
 */
public class RawSHAKE128 extends Keccak {

    public RawSHAKE128(int d) {
        super("RawSHAKE128(J," + d + ")", 256, d, (byte) 0x07);
    }
}
