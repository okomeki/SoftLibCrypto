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

import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.security.digest.SHA3Derived;
import net.siisise.security.digest.cSHAKE128;

/**
 * KECCAK Message Authentication Code
 * SHA-3系に用意されているらしい標準MAC
 * NIST SP 800-185
 * @deprecated まだ
 */
public class KMAC128 implements MAC {
    cSHAKE128 cshake;
    long L;

    @Override
    public void init(byte[] key) {
        init(key, 128, "");
    }
    
    public void init(byte[] key, int length, String S) {
        Packet newX = new PacketA();
        L = length;
        newX.write(SHA3Derived.bytepad(SHA3Derived.encode_string(key),168));
        cshake = new cSHAKE128(length, "KMAC", S);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        cshake.update(src, offset, length);
    }

    @Override
    public byte[] doFinal() {
        cshake.update(SHA3Derived.right_encode(L));
        return cshake.digest();
    }

    @Override
    public int getMacLength() {
        return cshake.getDigestLength();
    }
}
