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
package net.siisise.security.padding;

import java.security.MessageDigest;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.io.PacketA;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.lang.Bin;
import net.siisise.security.digest.SHA1;

/**
 * Mask Generation Function
 * RFC 8017 PKCS #1 B.2.1. MGF1
 */
public class MGF1 implements MGF {
    public static final OBJECTIDENTIFIER OID = PKCS1.id_mgf1;

    /**
     * デフォルト SHA1
     */
    private final MessageDigest hash;

    /**
     * 
     * @param hash オプション Hash hash finction (hLen denotes the length in octets of the hash function output)
     */
    public MGF1(MessageDigest hash) {
        this.hash = (hash == null) ? new SHA1() : hash;
    }

    /**
     * SHA1でMGFを作る.
     * @deprecated default SHA1が非推奨
     */
    @Deprecated
    public MGF1() {
        hash = new SHA1();
    }

    /**
     * Appendix B.2.1 にあるらしい. 限界は 配列サイズ
     * seed からのハッシュで疑似乱数を生成してmaskLenの長さのマスクを作るよ
     * @param mgfSeed mgfSeed mgfSeed from which mask is generated, an octet string
     * @param maskLen マスクのオクテット単位の長さ intended length in octets of the mask, at most 2^32 hLen
     * @return mask mask, an octet string of length maskLen
     */
    @Override
    public byte[] generate(byte[] mgfSeed, long maskLen) {
        PacketA T = new PacketA();
        if (maskLen > 0xffffffffl | maskLen < 0) {
            throw new SecurityException("mask too long");
        }
        int hLen = hash.getDigestLength();
        long cn = ((maskLen + hLen -1) / hLen);
        for ( long c = 0; c < cn; c++ ) {
            hash.update(mgfSeed);
            hash.update(Bin.toByte((int) c)); // PKCS!.I2OSP(c, 4)
            T.dwrite(hash.digest());
        }
        long len = T.length();
        if (len > maskLen) {
            T.backRead(new byte[(int) (T.length() - maskLen)]);
        }
        return T.toByteArray();
    }

}
