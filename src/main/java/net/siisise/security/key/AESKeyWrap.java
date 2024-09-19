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

import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;
import net.siisise.security.block.ES;
import net.siisise.security.mode.GCM;

/**
 * RFC 3394 Advanced Encryption Standard (AES) Key Wrap Algorithm.
 * RFC 5649 Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm.
 */
public class AESKeyWrap implements ES {

    Block aes;
//    private byte[] kek;
    
    /**
     * 初期設定.
     * 
     * @param kek 鍵暗号化鍵 コピーしないので注意.
     */
    public void init(byte[] kek) {
//        this.kek = kek;
        aes = new AES();
        aes.init(kek);
    }

    /**
     * @deprecated 仮
     * @param kek 
     */
    public void init(byte[][] kek) {
        aes = new GCM(new AES());
        aes.init(kek);
        
    }
    
    static long def = 0xa6a6a6a6a6a6a6a6l;
    
    /**
     * 
     * @param plain 64bit block x n
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] plain) {
        long a = def; // new long[1]; // IV ? See 2.2.3.
        long[] p = Bin.btol(plain);
        long[] r = new long[p.length + 1];
        System.arraycopy(p, 0, r, 1, p.length);

        long[] src = new long[2];
        
        for ( int j = 0; j <= 5; j++ ) {
            for ( int i = 1; i <= p.length; i++ ) {
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
        long a = c[0];
        long[] r = new long[c.length - 1];
        long[] b = new long[2];
        for ( int j = 5; j >= 0; j--) {
            for (int i = r.length; i > 0; i--) {
                b[0] = a ^ (r.length * j + i);
                b[1] = c[i];
                long[] src = aes.decrypt(b);
                a = src[0];
                c[i] = src[1];
            }
        }
        if ( a != def ) {
            throw new IllegalStateException();
        }
        System.arraycopy(c, 1, r, 0, r.length);
        return Bin.ltob(r);
    }
}
