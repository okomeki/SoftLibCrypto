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

import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.digest.SHA3Derived;
import net.siisise.security.digest.cSHAKE;

/**
 * Keccak MAC.
 * NIST SP 800-185
 * MACかXOF
 */
public abstract class KMAC implements MAC {
    private cSHAKE cshake;
    protected long L;

    // RFC 8702
    public static final OBJECTIDENTIFIER KmacWithSHAKE128 = new OBJECTIDENTIFIER("2.16.840.1.101.3.4.2.19");
    public static final OBJECTIDENTIFIER KmacWithSHAKE256 = new OBJECTIDENTIFIER("2.16.840.1.101.3.4.2.20");

    /**
     * 初期化要素.
     * @param c 暗号強度 128,256
     * @param key 鍵
     * @param length XOF出力サイズ bit
     * @param S オプションで設定可能な空文字列を含む可変長文字列. optional customization bit string of any length, including zero.
     */
    protected void init(int c, byte[] key, int length, String S) {
        L = length;
        cshake = new cSHAKE(c,length, "KMAC", S);
        byte[] newX = SHA3Derived.bytepad(SHA3Derived.encode_string(key), cshake.getBitBlockLength() / 8 );
        cshake.update(newX);
    }
    
    /**
     * 暗号強度はあらかじめ設定済みなので省けるかもしれず.
     * 
     * @param K 鍵
     * @param L 出力bitサイズ
     * @param S オプション可変長文字列
     */
    public abstract void init(byte[] K, int L, String S);

    @Override
    public void update(byte[] src, int offset, int length) {
        cshake.update(src, offset, length);
    }

    @Override
    public byte[] sign() {
        cshake.update(SHA3Derived.right_encode(L));
        return cshake.digest();
    }

    @Override
    public int getMacLength() {
        return cshake.getDigestLength();
    }
}
