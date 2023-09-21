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

import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.security.digest.SHA3Derived;
import net.siisise.security.digest.cSHAKE;

/**
 *
 */
public abstract class KMAC implements MAC {
    cSHAKE cshake;
    long L;
    
    public void init(int c, byte[] key, int length, String S) {
        Packet newX = new PacketA();
        L = length;
        newX.write(SHA3Derived.bytepad(SHA3Derived.encode_string(key),c == 128 ? 168 : 136 ));
        cshake = new cSHAKE(c,length, "KMAC", S);
        cshake.update(newX.toByteArray());
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
