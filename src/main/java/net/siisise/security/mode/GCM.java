/*
 * Copyright 2023 Siisise Net.
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
package net.siisise.security.mode;

import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;
import net.siisise.security.mac.GHASH;

/**
 * TLS 1.2のモードなど.
 * CTR の微修正.
 * https://scrapbox.io/standard/GCM
 * Galois/Counter Mode(GCMx) and GMAC NIST SP 800- 38D, November 2007
 * https://doi.org/10.6028/NIST.SP.800-38D
 * Counter は IV(96bit) + 1(32bit) らしい
 * P (plaintext)の長さ 2^39 -256 32bit counter の限界か
 * A (AAD: additional authenticated data)の長さ 2^64 -1
 * IVの長さ 2^64 -1
 * 
 * NIST SP 800-38D
 * RFC 5116
 * RFC 5288 AES Galois Counter Mode (GCM) Cipher Suite for TLS
 * GCMでのAESの使用について
 * RFC 5289 TLS Elliptic Curve Cipher Suites with SHA-256/384 and AES Galois Counter Mode (GCM)
 */
public class GCM extends LongStreamMode {
    
    static class GCTR extends CTR {
        GCTR(Block b) {
            super(b);
        }
        
        /**
         * vector LSB 32bitのみカウントする
         */
        @Override
        void next() {
            long u = vectorl[1] & 0xffffffff00000000l;
            long d = ++vectorl[1] & 0x00000000ffffffffl;
            vectorl[1] = u | d;
        }
    }
    
    private GCTR ctr;
    private byte[] iv;
    
    // GHASH
    private GHASH gh;
    
    private byte[] tag;
    
    private byte[] key;
    
    /**
     * AES-GCM にしよう.
     */
    public GCM() {
        super(new AES());
    }
    
    /**
     * AES GCM
     * @param block AES 他
     */
    public GCM(Block block) {
        super(block);
    }

    @Override
    public int getBlockLength() {
        return 128;
    }

    /**
     * 
     * iv 96bit または ?
     * iv は使い捨て( 再利用禁止、衝突するRNDよりCountがいい )
     * @param params key, Y0用iv, aad
     */
    @Override
    public void init(byte[]... params) {
        // iv 生成用AES?
        key = params[0];
        block.init(key); // Y0内で呼ぶので不要 CTRのinitは使わない

        // GHASH
        long[] H = block.encrypt(new long[block.getBlockLength() / 64]);

        iv = J0(H, params[1]); // block が状態遷移しないAES前提
        
        ctr = new GCTR(block);

        ctr.init(key,iv);
        ctr.next(); // データ用初期値 00000002

        byte[] aad;
        if ( params.length >= 3) {
            aad = params[2];
        } else {
            aad = new byte[0];
        }

        // GHASH
        tag = null;
        gh = new GHASH();
        gh.init(H, aad);
    }
    
    /**
     * Algorithm 4: GCM-AE_K(IV, P, A) Step 2.
     * @param iv 候補 96bit でも それ以外でもよし
     */
    private byte[] J0(long[] H, byte[] iv) {
        byte[] m = new byte[block.getBlockLength() / 8];
        if (iv.length == 12) { // 96 bit
            System.arraycopy(iv, 0, m, 0, iv.length);
            m[15]++;
            return m;
        }
        // 以下未確認
//        int s = (iv.length / 16 + 15)*128 - iv.length*8;
//        int s = (15 - (iv.length % 16));
        GHASH ivgh = new GHASH();
        ivgh.init(H);
        ivgh.update(iv);
        return ivgh.sign();
    }
    
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        byte[] c = ctr.encrypt(src, offset);
        gh.update(c);
        return c;
    }

    /**
     * ブロック用
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public int[] encrypt(int[] src, int offset) {
        int[] c = ctr.encrypt(src, offset);
        gh.update(Bin.itob(c));
        return c;
    }

    @Override
    public long[] encrypt(long[] src, int offset) {
        long[] c = ctr.encrypt(src, offset);
        gh.update(Bin.ltob(c));
        return c;
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        gh.update(Bin.itob(src, offset, 4));
        return ctr.encrypt(src, offset);
    }
    
    @Override
    public long[] decrypt(long[] src, int offset) {
        gh.update(Bin.ltob(src, offset, 2));
        return ctr.encrypt(src, offset);
    }

    /**
     * ストリーム用
     * @param src 元データ
     * @param offset 位置
     * @param length サイズ
     * @return 符号化
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        byte[] c = ctr.encrypt(src,offset,length);
        gh.update(c, 0, length);
        return c;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        gh.update(src, offset, length);
        return ctr.encrypt(src, offset, length);
    }

    public byte[] tag() {
        if ( tag == null ) {
            byte[] S = gh.sign();
            // CTR
            tag = block.encrypt(iv);
            Bin.xorl(tag, S);
        }
        return tag;
    }
}
