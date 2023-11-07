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
 * NIST SP 800-185 cSHAKE.
 * ビット列用だがバイト列で使う.
 * 
 */
public class cSHAKE extends Keccak {
    
    boolean c = false;
    
    /**
     * cSHAKE.
     * N, Sが空の場合はSHAKEと同じ
     * @param c セキュリティ強度 128 または 256
     * @param d 出力長
     * @param N 関数名のビット文字列
     * @param S 
     */
    public cSHAKE(int c, int d, String N, String S) {
        super("cSHAKE"+c+"(" + d + ")", 2 * c, d, (byte) 0x1f);
        if (N == null) {
            N = "";
        }
        if (S == null) {
            S = "";
        }
        if (!N.isEmpty() || !S.isEmpty()) {
            this.c = true;
            Packet p = new PacketA();
            p.write(SHA3Derived.encode_string(N.getBytes(StandardCharsets.UTF_8)));
            p.write(SHA3Derived.encode_string(S.getBytes(StandardCharsets.UTF_8)));
            byte[] x = SHA3Derived.bytepad(p, c == 128 ? 168 : 136);
            engineUpdate(x, 0, x.length);
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
