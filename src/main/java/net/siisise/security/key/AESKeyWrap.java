/*
 * Copyright 2024 okome.
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
package net.siisise.security.key;

import java.util.Arrays;
import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;
import net.siisise.security.block.ES;

/**
 * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm.
 * RFC 5649 Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm.
 */
public class AESKeyWrap implements ES {

    // RFC 3394
    final long def = 0xa6a6a6a6a6a6a6a6l;
    // RFC 5649
    final long aiv = 0xa65959a600000000l;

    boolean padding;
    Block aes;

    long a;

    public AESKeyWrap(AES a) {
        aes = a;
    }

    public AESKeyWrap() {
        aes = new AES();
    }

    /**
     * 初期設定.
     * RFC 3394
     * @param kek 鍵暗号化鍵 コピーしないので注意.
     */
    public void init(byte[] kek) {
        aes.init(kek);
        padding = false;
    }

    /**
     * RFC 5649 with Padding
     * @param kek 
     */
    public void initWithPadding(byte[] kek) {
        aes.init(kek);
        padding = true;
    }

    /**
     *
     * @param plain 64bit block x n
     * @return ciphertext 64bit x (n+1)
     */
    @Override
    public byte[] encrypt(byte[] plain) {
//        long a = def; // new long[1]; // IV ? See 2.2.3.
        if (padding) {
            a = aiv | ((long) plain.length) & 0xffffffffl;
            plain = Arrays.copyOf(plain, (plain.length + 7) & 0xfffffff8);
        } else {
            a = def;
        }

        long[] p = Bin.btol(plain);
        long[] r = new long[p.length + 1];
        System.arraycopy(p, 0, r, 1, p.length);

        long[] src = new long[2];

        for (int j = 0; j <= 5; j++) {
            for (int i = 1; i <= p.length; i++) {
                src[0] = a;
                src[1] = r[i];
                long[] b = aes.encrypt(src);
                a = b[0] ^ (p.length * j + i);
                r[i] = b[1];
            }
        }
        r[0] = a;
        return Bin.ltob(r);
    }

    @Override
    public byte[] decrypt(byte[] ciphertext) {
        long[] c = Bin.btol(ciphertext);
        a = c[0];
        long[] r = new long[c.length - 1];
        long[] b = new long[2];
        for (int j = 5; j >= 0; j--) {
            for (int i = r.length; i > 0; i--) {
                b[0] = a ^ (r.length * j + i);
                b[1] = c[i];
                long[] src = aes.decrypt(b);
                a = src[0];
                c[i] = src[1];
            }
        }
        byte[] plaintext = Bin.ltob(c, 1, r.length);
        if (padding) {
            int len = (int) (a & 0xffffffff);
            int rlen = r.length * 8;
            if ((a >>> 32) != (aiv >>> 32) || (len > rlen) || (len < rlen - 7)) {
                throw new IllegalStateException();
            }
            plaintext = Arrays.copyOf(plaintext, len);
        } else if (a != def) {
            throw new IllegalStateException();
        }
        return plaintext;
    }
}
