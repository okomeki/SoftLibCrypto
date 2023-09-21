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
package net.siisise.security.mac;

/**
 * KECCAK Message Authentication Code
 * SHA-3系に用意されているらしい標準MAC
 * NIST SP 800-185
 */
public class KMAC128 extends KMAC implements MAC {

    public KMAC128() {
    }

    @Override
    public void init(byte[] key) {
        init(key, 128, "");
    }
    
    public void init(byte[] key, int length, String S) {
        init(128,key,length,S);
    }
}
