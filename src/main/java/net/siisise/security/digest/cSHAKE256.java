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
package net.siisise.security.digest;

import java.nio.charset.StandardCharsets;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;

/**
 *
 */
public class cSHAKE256 extends Keccak {

    boolean c = false;

    public cSHAKE256(int d, String N, String S) {
        super("cSHAKE256(" + d + ")", 2 * 256, d, (byte) 0x1f);
        if (N == null) {
            N = "";
        }
        if (S == null) {
            S = "";
        }
        if (!N.isEmpty() || !S.isEmpty()) {
            c = true;
            Packet p = new PacketA();
            p.write(SHA3Derived.encode_string(N.getBytes(StandardCharsets.UTF_8)));
            p.write(SHA3Derived.encode_string(S.getBytes(StandardCharsets.UTF_8)));
            update(SHA3Derived.bytepad(p, 136));
        }
    }

    @Override
    protected byte[] engineDigest() {
        if (c) {
            engineUpdate(new byte[1], 0, 1);
        }
        return super.engineDigest();
    }

}
