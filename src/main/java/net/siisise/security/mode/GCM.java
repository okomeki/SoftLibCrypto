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

import java.util.Arrays;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
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
public class GCM extends LongStreamMode implements StreamAEAD {

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
     * nonce
     * @return nonce bit length
     */
    @Override
    public int[] getParamLength() {
        int[] pl = block.getParamLength();
        int[] np = Arrays.copyOf(pl, pl.length + 1);
        np[np.length - 1] = getBlockLength() - 32;
        return np;
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
        block.init(key);

        // GHASH
        gh = new GHASH();
        long[] H = block.encrypt(new long[block.getBlockLength() / 64]);
        gh.init(H);

        iv = J0(params[1]);

        ctr = new GCTR(block);

        ctr.init(key,iv);
        ctr.next(); // データ用初期値

        byte[] aad;
        if ( params.length >= 3) {
            aad = params[2];
        } else {
            aad = new byte[0];
        }

        // GHASH
        tag = null;
        gh.clear();
        gh.aad(aad);
    }
    
    /**
     * Algorithm 4: GCM-AE_K(IV, P, A) Step 2.
     * @param iv 候補 96bit でも それ以外でもよし
     */
    private byte[] J0(byte[] iv) {
        byte[] m = new byte[block.getBlockLength() / 8];
        if (iv.length == 12) { // 96 bit
            System.arraycopy(iv, 0, m, 0, iv.length);
            m[15]++;
            return m;
        }
        // 以下未確認
//        int s = (iv.length / 16 + 15)*128 - iv.length*8;
//        int s = (15 - (iv.length % 16));
        gh.aad(new byte[0]);
        gh.update(iv);
        return gh.sign();
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

    /**
     * 
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        gh.update(src, offset, length);
        return ctr.encrypt(src, offset, length);
    }

    /**
     * タグ単体で取得する.
     * @return 認証タグ
     */
    @Override
    public byte[] tag() {
        if ( tag == null ) {
            byte[] S = gh.sign();
            // CTR
            tag = block.encrypt(iv);
            Bin.xorl(tag, S);
        }
        return tag;
    }
    
    /**
     * タグを含む.
     * @param src
     * @param offset
     * @param length
     * @return 暗号 + 認証タグ
     */
    @Override
    public byte[] doFinalEncrypt(byte[] src, int offset, int length) {
        Packet pac = new PacketA();
        pac.write(encrypt(src, offset, length));
        pac.write(tag());
        return pac.toByteArray();
    }
    
    /**
     * MAC に必要な長さが含まれる前提.
     * @param src 認証コードを含む
     * @param offset
     * @param length 16以上
     * @return 
     */
    @Override
    public byte[] doFinalDecrypt(byte[] src, int offset, int length) {
        byte[] dec = decrypt(src, offset, length - 16);
        byte[] t = tag();
//        byte[] st = Arrays.copyOfRange(src, offset + length - 16, 16);
//        if (!Arrays.equals(t, st)) {
        if (!Arrays.equals(t, 0, 16, src, offset + length - 16, 16)) {
            throw new IllegalStateException();
        }
        return dec;
    }
}
