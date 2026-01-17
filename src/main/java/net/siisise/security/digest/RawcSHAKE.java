/*
 * Copyright 2026 okome.
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

/**
 * XOF なしのベース実装.
 * NIST SP 800-185 3. cSHAKE
 * 
 * cSHAKE128とcSHAKE256 の元
 */
public class RawcSHAKE extends Keccak {

    /**
     * cSHAKE 初期
     * 
     * @param c キャパシティ 128, 256
     * @param L 出力ビット長 bit
     * @param N function-name bit string ファンクション名
     * @param S customization bit string 付加文字
     */
    RawcSHAKE(int c, long L, String N, String S) {
        this("cSHAKE"+c,c,L,N,S);
    }

    /**
     * cSHAKE 初期
     * 
     * @param name プロトコル名
     * @param c キャパシティ 128, 256
     * @param L 出力ビット長 bit
     * @param N function-name bit string ファンクション名
     * @param S customization bit string 付加文字
     */
    RawcSHAKE(String name, int c, long L, String N, String S) {
        super(name, 2 * c, L,
                ((N != null && !N.isEmpty()) || (S != null && !S.isEmpty())) ? 0x04 : 0x1f,
                ((N != null && !N.isEmpty()) || (S != null && !S.isEmpty())) ? 3 : 5);
        if (N == null) {
            N = "";
        }
        if (S == null) {
            S = "";
        }
        if (!N.isEmpty() || !S.isEmpty()) {
            Packet p;
            p = SHA3Derived.encode_string(N.getBytes(StandardCharsets.UTF_8));
            p.write(SHA3Derived.encode_string(S.getBytes(StandardCharsets.UTF_8)));
            byte[] x = SHA3Derived.bytepad(p, getBitBlockLength() / 8);
            // KeccakのengineUpdate を呼びたいが継承されることもあるのでsuper.をつけておく
            super.engineUpdate(x, 0, x.length);
        }
    }
}
