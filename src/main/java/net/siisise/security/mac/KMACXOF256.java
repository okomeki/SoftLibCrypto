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
package net.siisise.security.mac;

import net.siisise.security.digest.SHA3Derived;

/**
 * XOF 可変長っぽく.
 */
public class KMACXOF256 extends KMAC256 {

    @Override
    public byte[] doFinal() {
        cshake.update(SHA3Derived.right_encode(0));
        return cshake.digest();
    }
}
