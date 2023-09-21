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
import net.siisise.security.mode.CBC;

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
    CBC cbc;

    byte[] k1; // L・2 最後のブロックがブロック長と等しい場合
    byte[] k2; // k1・2 最後のブロックがブロック長より短い場合
    private long len;
    private Packet m;

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
        cbc = new CBC(block);
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

    @Override
    public void update(byte[] src, int offset, int length) {
        len += length;
        int ml = m.size();
        int last = offset + length;
        // Strp 6. A
        if ( ml > 0 && ml + length > k1.length ) {
            int wlen = k1.length - ml;
            m.write(src,offset,wlen);
            offset += wlen;
            cbc.encrypt(m.toByteArray(), 0);
        }
        while ( offset + k1.length < last ) {
            cbc.encrypt(src,offset);
            offset += k1.length;
        }
        m.write(src, offset, last - offset);
    }

    @Override
    public byte[] doFinal() {
        // Step 3. Step 4.
        byte[] T;
        if ( (len == 0) || ( len % k1.length != 0 ) ) { // padding(M)
            m.write(0x80);
            m.write(new byte[k2.length - m.size()]);
            T = m.toByteArray();
            Bin.xorl(T, k2);
        } else {
            T = m.toByteArray();
            Bin.xorl(T, k1);
        }
        T = cbc.encrypt(T);
        // Step 6. B Step 7.
        // 次の初期化
        cbc = new CBC(block); // Blockのkeyはそのまま、CBCのIVだけ初期化したい
        len = 0;
        return T;
    }

    @Override
    public int getMacLength() {
        return (block.getBlockLength() + 7) / 8;
    }

    
}
