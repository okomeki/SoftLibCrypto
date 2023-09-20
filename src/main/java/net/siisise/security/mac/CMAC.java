/*
 * Copyright 2022 Siisise Net.
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
import net.siisise.lang.Bin;
import net.siisise.math.GF;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;

/**
 * Cipher-based Message Authentication Code (CMAC).
 * 
 * OMAC は OMAC1 と OMAC2 の総称
 * OMAC1 は CMAC と同じ、これはCMAC
 * http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
 * 
 * GFなどで128bit または64bit 固定なのかも.
 * 
 * One-Key CBC MAC1 (OMAC1) と同じ
 * 
 * CBC-MAC の更新
 * XCBC / OMAC / CMAC = OMAC1 / TMAC
 * 
 * Tetsu Iwata, Kaoru Kurosawa、OMAC: One-Key CBC MAC、2003年、Fast Software Encryption, FSE 2003, LNCS 2887, pp. 129-153, Springer.
 * 
 * RFC 4493 The AES-CMAC Algorithm.
 * NIST SP 800-38B Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication.
 */
public class CMAC implements MAC {

    private final Block block; // E

    byte[] k1; // L・2 最後のブロックがブロック長と等しい場合
    byte[] k2; // k1・2 最後のブロックがブロック長より短い場合
    private long len;
    private Packet m;
    // Step 5.
    private byte[] x;

    /**
     * AES-CMAC.
     */
    public CMAC() {
        this(new AES());
    }

    /**
     * AES-CMAC
     * @param key AES key 128bit
     */
    public CMAC(byte[] key) {
        this(new AES());
        init(key);
    }

    /**
     * 特定のブロック暗号のCMACっぽいものにする?
     * XXX-CMAC
     * 別途init必要
     * @param e ブロック暗号 E 
     */
    public CMAC(Block e) {
        block = e;
    }

    /**
     * RFC 4493 Section 2.3. Subkey Generation Algorithm
     * @param key AES鍵 AES-128 128bit AES-192 AES-256 でもいいかも
     */
    @Override
    public void init(byte[] key) {
        // Generate_Subkey
        block.init(key);
        int blen = getMacLength();
        byte[] L = block.encrypt(new byte[blen]);
        // RFC 4493にガロア体の説明はないが、実体はガロア体 OMAC1a に説明がある?
        GF gf;
        if (blen == 16) { // AES 128bit
            gf = new GF(blen*8,GF.FF128); // 0x87
        } else { // TDEA TripleDES 64bit 8bitも同じ
            gf = new GF(blen*8,GF.FF64 ); // 0x1b
        }
        initk(L,gf);
        // Generate_Subkey ここまで
        m = new PacketA();
        len = 0;
        // Step 5.
        x = new byte[blen];
    }

    /**
     * OMAC1 と OMAC2で違いそうなところ
     * @param L
     * @param gf 
     */
    void initk(byte[] L, GF gf) {
        k1 = gf.x(L);
        k2 = gf.x(k1);
    }
/*    
    private void step6a() {
        // Step 6. A
        byte[] mi = new byte[x.length];
        long mlen = m.length();
        while ( mlen > x.length ) {
            m.read(mi);
            enc(mi);
            mlen -= x.length;
        }
    }
*/
    /**
     * CBC 相当
     * x = Ek(x^a)
     * @param a データ
     */
    private void enc(byte[] a, int offset) {
        for ( int i = 0; i < x.length; i++ ) {
            x[i] ^= a[offset + i];
        }
        x = block.encrypt(x);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        len += length;
        int ml = m.size();
        int last = offset + length;
        // Strp 6. A
        if ( ml > 0 && ml + length > x.length ) {
            int wlen = x.length - ml;
            m.write(src,offset,wlen);
            offset += wlen;
            enc(m.toByteArray(), 0);
        }
        while ( offset + x.length < last ) {
            enc(src,offset);
            offset += x.length;
        }
        m.write(src, offset, last - offset);
    }

    @Override
    public byte[] doFinal() {
        // Step 3. Step 4.
        if ( (len == 0) || ( len % k1.length != 0 ) ) { // padding(M)
            m.write(0x80);
            m.write(new byte[k2.length - m.size()]);
            Bin.xorl(x, k2);
        } else {
            Bin.xorl(x, k1);
        }
        Bin.xorl(x, m.toByteArray());
        // Step 6. B Step 7.
        byte[] T = block.encrypt(x);
        // 次の初期化
        x = new byte[x.length];
        len = 0;
        return T;
    }

    @Override
    public int getMacLength() {
        return (block.getBlockLength() + 7) / 8;
    }

    
}
