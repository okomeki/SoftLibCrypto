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
package net.siisise.security.block;

import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.lang.Bin;
import net.siisise.security.mode.CBC;
import net.siisise.security.mode.CCM;
import net.siisise.security.mode.CFB;
import net.siisise.security.mode.ECB;
import net.siisise.security.mode.GCM;
import net.siisise.security.mode.OFB;
import net.siisise.security.mode.PKCS7Padding;

/**
 * Adbanced Encryption Standard.
 * FIPS 197
 * Rijndael という名称.
 *
 * ソフト実装で他より速いはず。
 * 安全(テーブル使用なので計算差なし)。
 *
 * https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
 * RoundKey参考
 * https://qiita.com/tobira-code/items/152befa86bd515f67241
 * MixColumns
 * https://tex2e.github.io/blog/crypto/aes-mix-columns
 */
public class AES extends IntBlock {

    /**
     * joint-iso-ccitt(2) country(16) us(840) organization(1) gov(101) csor(3) nistAlgorithm(4)
     * https://csrc.nist.gov/Projects/computer-security-objects-register/algorithm-registration
     */
    public static final OBJECTIDENTIFIER nistAlgorithms = new OBJECTIDENTIFIER("2.16.840.1.101.3.4");
    
    // modules
    public static final OBJECTIDENTIFIER csorModules = nistAlgorithms.sub(0);
    // modules aes
    public static final OBJECTIDENTIFIER aesModule1 = csorModules.sub(1);
    
    public static final OBJECTIDENTIFIER AES = nistAlgorithms.sub(1);
    public static final OBJECTIDENTIFIER aes128_ECB_PAD = AES.sub(1);
    public static final OBJECTIDENTIFIER aes128_CBC_PAD = AES.sub(2);
    public static final OBJECTIDENTIFIER aes128_OFB = AES.sub(3);
    public static final OBJECTIDENTIFIER aes128_CFB = AES.sub(4);
    public static final OBJECTIDENTIFIER aes128_wrap = AES.sub(5); // AES key wrap
    public static final OBJECTIDENTIFIER aes128_GCM = AES.sub(6);
    public static final OBJECTIDENTIFIER aes128_CCM = AES.sub(7);
    public static final OBJECTIDENTIFIER aes128_wrap_pad = AES.sub(8); // AES key wrap with Padding KEK
    public static final OBJECTIDENTIFIER aes192_ECB_PAD = AES.sub(21);
    public static final OBJECTIDENTIFIER aes192_CBC_PAD = AES.sub(22);
    public static final OBJECTIDENTIFIER aes192_OFB = AES.sub(23);
    public static final OBJECTIDENTIFIER aes192_CFB = AES.sub(24);
    public static final OBJECTIDENTIFIER aes192_wrap = AES.sub(25); // AES key wrap
    public static final OBJECTIDENTIFIER aes192_GCM = AES.sub(26);
    public static final OBJECTIDENTIFIER aes192_CCM = AES.sub(27);
    public static final OBJECTIDENTIFIER aes192_wrap_pad = AES.sub(28); // AES key wrap with Padding KEK
    public static final OBJECTIDENTIFIER aes256_ECB_PAD = AES.sub(41);
    public static final OBJECTIDENTIFIER aes256_CBC_PAD = AES.sub(42);
    public static final OBJECTIDENTIFIER aes256_OFB = AES.sub(43);
    public static final OBJECTIDENTIFIER aes256_CFB = AES.sub(44);
    public static final OBJECTIDENTIFIER aes256_wrap = AES.sub(45); // AES key wrap
    public static final OBJECTIDENTIFIER aes256_GCM = AES.sub(46);
    public static final OBJECTIDENTIFIER aes256_CCM = AES.sub(47);
    public static final OBJECTIDENTIFIER aes256_wrap_pad = AES.sub(48); // AES key wrap with Padding KEK

    /**
     * OIDから暗号.
     * @param alg OID
     * @return 該当しない場合は null
     */
    public static Block toBlockPad(OBJECTIDENTIFIER alg) {
        if ( alg.up().equals(AES)) {
            int sub = (int)alg.getLast();
            Block b;
            switch (sub / 20) {
                case 0: b = new AES(128);   break;
                case 1: b = new AES(192);   break;
                case 2: b = new AES(256);   break;
                default:
                    return null;
            }
            switch (sub % 20) {
                case 1: b = new PKCS7Padding(new ECB(b));   break;
                case 2: b = new PKCS7Padding(new CBC(b));   break;
                case 3: b = new OFB(b); break;
                case 4: b = new CFB(b); break;
                // 5 AES Key Wrap
                case 6: b = new GCM(b); break;
                case 7: b = new CCM(b); break;
                // 8 AES Key Wrap with Padding
                default:
                    return null;
            }
            return b;
        }
        return null;
    }

    /**
     * Rijndael 128～256ビット 32ビット単位
     * AES 128bit固定
     */
    private final int blockLength = 128;
    private final int keyLength;

    private static final int[] Rcon = new int[11];

    private static final long[] SBOX = new long[256]; // FIPS 197-upd1 Table 4.
    private static final long[] LMIX0 = new long[256];
    private static final long[] LMIX1 = new long[256];
    private static final long[] LMIX2 = new long[256];
    private static final long[] LMIX3 = new long[256];
    private static final long[] IBOX = new long[256];
    private static final long[] IMIX0 = new long[256];
    private static final long[] IMIX1 = new long[256];
    private static final long[] IMIX2 = new long[256];
    private static final long[] IMIX3 = new long[256];

    static {
        // 2・n
        final int[] GF = new int[256];
        final int[] logGF = new int[256];
        final int[] expGF = new int[256];

        // テーブルにしてしまうといろいろ省略できる 使い捨てだが関数でもいい
        for (int i = 1; i < 256; ++i) {
            // 1と1bに分けずにシフト演算でまとめる
            GF[i] = (i << 1) ^ ((i >> 7) * 0x11b);
        } // m(x) = x^8 + x^4 * x^3 + x + 1 のビット 100011011 = 0x11b

        // sboxつくる
        // https://tociyuki.hatenablog.jp/entry/20160427/1461721356
        // を元に高速化したもの
        int n = 1;
        for (int e = 0; e < 255; e++) {
            logGF[n] = e;
            expGF[e] = n;
            n ^= GF[n]; // 3・n
        }
        logGF[0] = 0;
        expGF[255] = expGF[0];

        for (int i = 0; i < 256; ++i) {
            // r ガロア体の逆数変換 1回しか使わないので使い捨て
            int r = (i == 0) ? 0 : expGF[255 - logGF[i]];  // むつかしいところ
            int s = r ^ (r << 1) ^ (r << 2) ^ (r << 3) ^ (r << 4);
            s = 0x63 ^ s ^ ((s >> 8) * 0x101); // 手抜きローテート
//            System.out.println("r " + r + " rgf " + rgf[i] + " rgf3 "+ (rgf[rgf[i]] ^ rgf[i]) + " s " + s);

            SBOX[i] = s;
            /*
            // 個別で逆も計算できるが省略
            r = (i << 1) ^ (i << 3) ^ (i << 6) ^ 0x5;
            r = (r ^ ( r >> 8)) & 0xff;
            ibox[i] = (r == 0) ? 0 : expGF[255 - logGF[r]];
/*/
            IBOX[s] = i;
//*/
            int gf2 = GF[s]; // 前段階のsboxを含める
            // 1,2,3しかないのに個別に mulとかしてはいけない
            // XOR で演算できるので 3は1と2を合成するだけ
            // sbox込み あとで XOR できるところまで計算

            LMIX0[i] = s * 0x00010101l ^ gf2 * 0x01000001l;
            LMIX1[i] = s * 0x01000101l ^ gf2 * 0x01010000l;
            LMIX2[i] = s * 0x01010001l ^ gf2 * 0x00010100l;
            LMIX3[i] = s * 0x01010100l ^ gf2 * 0x00000101l;

            // 同じ原理で個別の計算を省略する
            gf2 = GF[i];
            int gf4 = GF[gf2];
            long gf7x = i ^ (gf2 * 0x101) ^ (gf4 * 0x10001l);
            long gf9x = ((long)GF[gf4] ^ i) * 0x01010101l;

            // iboxあり
            IMIX0[s] = gf9x ^ ((gf7x << 24) ^ (gf7x >>> 8)) & 0xffffffffl;
            IMIX1[s] = gf9x ^ ((gf7x << 16) ^  gf4) & 0xffffffffl;
            IMIX2[s] = gf9x ^ (gf7x <<  8) & 0xffffffffl;
            IMIX3[s] = gf9x ^  gf7x;
        }

        // upd1 5.2. Table 5. Round constants
        n = 1;
        for (int i = 1; i < 11; i++) { // 使う範囲で生成
            Rcon[i] = n << 24;
            n = GF[n];
        }
    }

    @Override
    public int getBlockLength() {
        return blockLength;
    }

    /**
     * subWord(rotate(t))
     *
     * @param t
     * @return
     */
    private static int rotsubWord(int t) {
        return (int)((SBOX[t >>  16 & 0xff] << 24)
             | (SBOX[t >>   8 & 0xff] << 16)
             | (SBOX[t        & 0xff] << 8)
             |  SBOX[t >>> 24       ]);
    }

    /**
     *
     * @param word
     * @return
     */
    private static int subWord(int word) {
        return (int)((SBOX[word >>> 24       ] << 24)
             | (SBOX[word >>  16 & 0xff] << 16)
             | (SBOX[word >>   8 & 0xff] << 8)
             |  SBOX[word        & 0xff]);
    }

    private static final int Nb = 4;
    private int Nr4;

    /**
     * ラウンド鍵
     */
    private int[] w;
    /**
     * ラウンド鍵 long用
     */
    private long[] lw;
    /**
     * InvMixColumns(ラウンド鍵)
     */
    private long[] ldw;

    public AES() {
        keyLength = 128;
    }
    
    public AES(int bit) {
        keyLength = bit;
    }
    
    @Override
    public int[] getParamLength() {
        return new int[] {keyLength};
    }
    
    /**
     * 鍵.
     * AESは128bit長.
     * keyExpansion()
     *
     * @param keys 128,192,256bit (16,24,32byte)のいずれか
     */
    @Override
    public void init(byte[]... keys) {
        byte[] key = keys[0];

        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new SecurityException("key length (" + key.length + ")");
        }

        int Nk = key.length / 4; // ぐらい 4 6 8
        int Nr = Nk + 6;         // ラウンド数 10 12 14
        Nr4 = Nr * 4;

        // ラウンド鍵の初期化 ワード列版 128*11?
        w = new int[Nb * (Nr + 1)];
        Bin.btoi(key, 0, w, Nk);
        int temp;
        for (int i = Nk; i < Nb * (Nr + 1); i++) {
            temp = w[i - 1];
            if (i % Nk == 0) {
                temp = rotsubWord(temp) ^ Rcon[i / Nk];
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
            w[i] = w[i - Nk] ^ temp;
        }

        lw = new long[(Nr+1)*2];
        Bin.itol(w,0,lw,lw.length);

        // デコード用ラウンド鍵 + MixColumns
        ldw = new long[(w.length - 4)/2];
        for ( int i = Nb; i < Nb * Nr; i+= Nb) {
            for (int c = 0; c < 2; c++ ) {
                int d = subWord(w[i+c*2]); // IMIX0はibox込みなのでiboxをsboxで消す
                ldw[i/2+c] = IMIX0[d >>> 24]
                        ^ IMIX1[(d >> 16) & 0xff]
                        ^ IMIX2[(d >>  8) & 0xff]
                        ^ IMIX3[ d        & 0xff];
                ldw[i/2+c] <<= 32;
                d = subWord(w[i+c*2+1]); // IMIX0はibox込みなのでiboxをsboxで消す
                ldw[i/2+c] |= IMIX0[d >>> 24]
                        ^ IMIX1[(d >> 16) & 0xff]
                        ^ IMIX2[(d >>  8) & 0xff]
                        ^ IMIX3[ d        & 0xff];
            }
        }
    }

    /**
     * 並列化できそう
     *
     * @param src 元データ
     * @param offset 位置
     * @param length サイズ
     * @return 暗号列
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        byte[] ret = new byte[length];
        int of = 0;

        while (length > of) {
            byte[] x = encrypt(src, offset);
            System.arraycopy(x, 0, ret, of, x.length);
            offset += x.length;
            of += x.length;
        }
        return ret;
    }

    /**
     * AES エンコード
     * AMD Ryzen 5 2600X で AES/CBCで 950Mbpsを超える
     *
     * @param src planetext 16byte
     * @param offset 先頭位置
     * @return chipertext
     */
    @Override
    public byte[] encrypt(final byte[] src, int offset) {
        long a = 0, b = 0;
        int nr = Nr4 / 2;
        for (int i = 0; i < 8; i++) {
            a <<= 8;
            a |= src[offset + i] & 0xff;
            b <<= 8;
            b |= src[offset + i + 8] & 0xff;
        }
        // AddRoundKey
        a ^= lw[0];
        b ^= lw[1];

        for (int r = 2; r < nr; r += 2) {
            // SubBytes + ShiftRow + MixColumns
            long e, g;
            e  = LMIX0[(int)(a >>> 0x38)]
              ^  LMIX1[(int)(a >>  0x10) & 0xff];
            g  = LMIX0[(int)(b >>> 56)]
              ^  LMIX1[(int) b >> 0x10  & 0xff];
            e ^= LMIX2[(int)(b >> 40) & 0xff]
              ^  LMIX3[(int) b        & 0xff];
            g ^= LMIX2[(int)(a >> 40) & 0xff]
              ^  LMIX3[(int) a        & 0xff];
            e <<= 32;
            g <<= 32;
            e ^= LMIX0[(int)(a >> 24) & 0xff]
              ^  LMIX1[(int)(b >> 48) & 0xff];
            g ^= LMIX0[(int) b >> 24  & 0xff];
            g ^= LMIX1[(int)(a >> 48) & 0xff];
            e ^= LMIX2[(int) b >>  8  & 0xff]
              ^  LMIX3[(int)(a >> 32) & 0xff];
            g ^= LMIX2[(int)(a >>  8) & 0xff];
            g ^= LMIX3[(int)(b >> 32) & 0xff];

            // AddRoundKey
            a = e ^ lw[r];
            b = g ^ lw[r+1];
        }

        // SubBytes + ShiftRows
        int e, f, g, d;
        e =  (int)((SBOX[(int)(a >>> 56)] << 24)
          |  (SBOX[(int)(a >> 16) & 0xff] << 16));
        e |= (int)((SBOX[(int)(b >> 40) & 0xff] << 8)
          |   SBOX[(int) b        & 0xff]);
        f =  (int)((SBOX[(int)(a >> 24) & 0xff] << 24)
          |  (SBOX[(int)(b >> 48) & 0xff] << 16));
        f |= (int)((SBOX[(int)(b >>  8) & 0xff] << 8)
          |   SBOX[(int)(a >> 32) & 0xff]);
        g  = (int)((SBOX[(int)(b >> 56) & 0xff] << 24)
          |  (SBOX[(int)(b >> 16) & 0xff] << 16));
        g |= (int)((SBOX[(int)(a >> 40) & 0xff] << 8)
          |   SBOX[(int) a        & 0xff]);
        d  = (int)((SBOX[(int)(b >> 24) & 0xff] << 24)
          |  (SBOX[(int)(a >> 48) & 0xff] << 16)
          |  (SBOX[(int)(a >> 8) & 0xff] << 8)
          |   SBOX[(int)(b >> 32) & 0xff]);

        // AddRoundKey
        return Bin.itob(new int[] {
            e ^ w[Nr4] ,
            f ^ w[Nr4 + 1],
            g ^ w[Nr4 + 2],
            d ^ w[Nr4 + 3]
        });
    }

    /**
     * AES エンコード
     * AMD Ryzen 5 2600X で AES/CBCで 950Mbpsを超える
     * AMD Ryzen 7 5800X で AES/CBCで 1500Mbpsを超える
     *
     * @param src planetext 16byte
     * @param offset 先頭位置
     * @return chipertext
     */
    @Override
    public int[] encrypt(final int[] src, int offset) {
        long a, b;
        a = ((long)src[offset]) << 32;
        a |= src[offset+1] & 0xffffffffl;
        b = ((long)src[offset+2]) << 32;
        b |= src[offset+3] & 0xffffffffl;
        // AddRoundKey
        a ^= lw[0];
        b ^= lw[1];
        int nr = Nr4/2;

        for (int r = 2; r < nr; r+=2) {
            // SubBytes + ShiftRow + MixColumns
            long c, d;
            c  = LMIX0[(int)(a >>> 0x38)]
              ^  LMIX1[(int)(a >> 16) & 0xff];
            d  = LMIX0[(int)(b >>> 56)]
              ^  LMIX1[(int)(b >> 16) & 0xff];
            c ^= LMIX2[(int)(b >> 40) & 0xff]
              ^  LMIX3[(int)b & 0xff];
            d ^= LMIX2[(int)(a >> 40) & 0xff]
              ^  LMIX3[(int)a & 0xff];
            c <<= 32;
            d <<= 32;
            c ^= LMIX0[(int)(a >> 24) & 0xff]
              ^  LMIX1[(int)(b >> 48) & 0xff];
            d ^= LMIX0[(int)(b >> 24) & 0xff];
            d ^= LMIX1[(int)(a >> 48) & 0xff];
            c ^= LMIX2[(int)(b >> 8) & 0xff]
              ^  LMIX3[(int)(a >> 32) & 0xff];
            d ^= LMIX2[(int)(a >> 8) & 0xff];
            d ^= LMIX3[(int)(b >> 32) & 0xff];

            // AddRoundKey
            a = c ^ lw[r];
            b = d ^ lw[r+1];
        }

        // SubBytes + ShiftRows
        int e, f, g, h;
        e =  (int)((SBOX[(int)(a >>> 56)] << 24)
          |  (SBOX[(int)(a >> 16) & 0xff] << 16));
        e |= (int)((SBOX[(int)(b >> 40) & 0xff] << 8)
          |   SBOX[(int) b        & 0xff]);
        f =  (int)((SBOX[(int)(a >> 24) & 0xff] << 24)
          |  (SBOX[(int)(b >> 48) & 0xff] << 16));
        f |= (int)((SBOX[(int)(b >>  8) & 0xff] << 8)
          |   SBOX[(int)(a >> 32) & 0xff]);
        g  = (int)((SBOX[(int)(b >> 56) & 0xff] << 24)
          |  (SBOX[(int)(b >> 16) & 0xff] << 16));
        g |= (int)((SBOX[(int)(a >> 40) & 0xff] << 8)
          |   SBOX[(int) a        & 0xff]);
        h  = (int)((SBOX[(int)(b >> 24) & 0xff] << 24)
          |  (SBOX[(int)(a >> 48) & 0xff] << 16)
          |  (SBOX[(int)(a >> 8) & 0xff] << 8)
          |   SBOX[(int)(b >> 32) & 0xff]);

        // AddRoundKey
        return new int[] {
            e ^ w[Nr4] ,
            f ^ w[Nr4 + 1],
            g ^ w[Nr4 + 2],
            h ^ w[Nr4 + 3]
        };
    }

    /**
     * AES エンコード
     * AMD Ryzen 5 2600X で AES/CBCで 950Mbpsを超える
     * AMD Ryzen 7 5800X で AES/CBCで 1500Mbpsを超える
     *
     * @param src planetext 16byte
     * @param offset 先頭位置
     * @return chipertext
     */
    @Override
    public long[] encrypt(final long[] src, int offset) {
        long a, b;
        int nr = Nr4/2;
        // AddRoundKey
        a = src[offset] ^ lw[0];
        b = src[offset+1] ^ lw[1];

        for (int r = 2; r < nr; r+=2) {
            // SubBytes + ShiftRow + MixColumns
            long c, d;
            c  = LMIX0[(int)(a >>> 0x38)]
              ^  LMIX1[(int)(a >> 16) & 0xff];
            d  = LMIX0[(int)(b >>> 56)]
              ^  LMIX1[(int)(b >> 16) & 0xff];
            c ^= LMIX2[(int)(b >> 40) & 0xff]
              ^  LMIX3[(int)b & 0xff];
            d ^= LMIX2[(int)(a >> 40) & 0xff]
              ^  LMIX3[(int)a & 0xff];
            c <<= 32;
            d <<= 32;
            c ^= LMIX0[(int)(a >> 24) & 0xff]
              ^  LMIX1[(int)(b >> 48) & 0xff];
            d ^= LMIX0[(int)(b >> 24) & 0xff];
            d ^= LMIX1[(int)(a >> 48) & 0xff];
            c ^= LMIX2[(int)(b >> 8) & 0xff]
              ^  LMIX3[(int)(a >> 32) & 0xff];
            d ^= LMIX2[(int)(a >> 8) & 0xff];
            d ^= LMIX3[(int)(b >> 32) & 0xff];

            // AddRoundKey
            a = c ^ lw[r];
            b = d ^ lw[r+1];
        }

        // SubBytes + ShiftRows
        long e, f;
        e =  (SBOX[(int)(a >>> 56)]       << 56)
          |  (SBOX[(int)(a >> 16) & 0xff] << 48);
        e |= (SBOX[(int)(b >> 40) & 0xff] << 40)
          |  (SBOX[(int) b        & 0xff] << 32);
        e |= (SBOX[(int)(a >> 24) & 0xff] << 24)
          |  (SBOX[(int)(b >> 48) & 0xff] << 16);
        e |= (SBOX[(int)(b >>  8) & 0xff] << 8)
          |   SBOX[(int)(a >> 32) & 0xff];
        f  = (SBOX[(int)(b >> 56) & 0xff] << 56)
          |  (SBOX[(int)(b >> 16) & 0xff] << 48);
        f |= (SBOX[(int)(a >> 40) & 0xff] << 40)
          |  (SBOX[(int) a        & 0xff] << 32);
        f |= (SBOX[(int)(b >> 24) & 0xff] << 24)
          |  (SBOX[(int)(a >> 48) & 0xff] << 16)
          |  (SBOX[(int)(a >> 8) & 0xff] << 8)
          |   SBOX[(int)(b >> 32) & 0xff];

        // AddRoundKey
        return new long[] {
            e ^ lw[nr] ,
            f ^ lw[nr + 1]
        };
    }

    /**
     * CBCなどで使う
     * AES/CBC
     * AMD Ryzen 7 5800X 1490Mbps 程度
     * @param src int型に納めた元
     * @param offset 復号化位置
     * @return 
     */
    @Override
    public int[] decrypt(final int[] src, final int offset) {
        long a, b;
        int nr = Nr4 / 2;
        a = (long)src[offset + 0] << 32;
        a |= src[offset + 1] & 0xffffffffl;
        b = (long)src[offset + 2] << 32;
        b |= src[offset + 3] & 0xffffffffl;
        a ^= lw[nr];
        b ^= lw[nr+1];

        for (int r4 = nr - 2; r4 > 0; r4 -= 2) {
            long c, e;

            c =  IMIX0[(int)(a >>> 56)       ]
              ^  IMIX1[(int)(b >>  16) & 0xff];
            e =  IMIX0[(int)(b >>> 56)       ]
              ^  IMIX1[(int)(a >>  16) & 0xff];
            c ^= IMIX2[(int)(b >>  40) & 0xff]
              ^  IMIX3[(int) a         & 0xff];
            e ^= IMIX2[(int)(a >>  40) & 0xff]
              ^  IMIX3[(int) b         & 0xff];
            c <<= 32;
            e <<= 32;
            c ^= IMIX0[(int)(a >>  24) & 0xff]
              ^  IMIX1[(int)(a >>  48) & 0xff];
            e ^= IMIX0[(int)(b >>  24) & 0xff]
              ^  IMIX1[(int)(b >>  48) & 0xff];
            c ^= IMIX2[(int)(b >>   8) & 0xff]
              ^  IMIX3[(int)(b >>  32) & 0xff];
            e ^= IMIX2[(int)(a >>   8) & 0xff]
              ^  IMIX3[(int)(a >>  32) & 0xff];
            a = c ^ ldw[r4];
            b = e ^ ldw[r4+1];
        }

        int c, d, e, f;
        c  = (int)(IBOX[(int)(a >>> 56)       ] << 24
          ^  IBOX[(int)(b >>  16) & 0xff] << 16);
        c ^= IBOX[(int)(b >>  40) & 0xff] << 8;
        c ^= IBOX[(int) a         & 0xff];
        d  = (int)(IBOX[(int)(a >>  24) & 0xff] << 24
          ^  IBOX[(int)(a >>  48) & 0xff] << 16);
        d ^= IBOX[(int)(b >>   8) & 0xff] << 8
          ^  IBOX[(int)(b >>  32) & 0xff];
        e  = (int)(IBOX[(int)(b >>> 56)       ] << 24
          ^  IBOX[(int)(a >>  16) & 0xff] << 16);
        e ^= IBOX[(int)(a >>  40) & 0xff] << 8;
        e ^= IBOX[(int) b         & 0xff];
        f  = (int)(IBOX[(int)(b >>  24) & 0xff] << 24
          ^  IBOX[(int)(b >>  48) & 0xff] << 16);
        f ^= IBOX[(int)(a >>   8) & 0xff] << 8;
        f ^= IBOX[(int)(a >>  32) & 0xff];

        return new int[] {
            c ^ w[0],
            d ^ w[1],
            e ^ w[2],
            f ^ w[3]};
    }


    /**
     * CBCなどで使う
     * AES/CBC
     * AMD Ryzen 7 5800X 1490Mbps 程度
     * @param src int型に納めた元
     * @param offset 復号化位置
     * @return 
     */
    @Override
    public long[] decrypt(final long[] src, final int offset) {
        long a, b;
        int nr = Nr4 / 2;
        a = src[offset    ] ^ lw[nr];
        b = src[offset + 1] ^ lw[nr+1];

        for (int r4 = nr - 2; r4 > 0; r4 -= 2) {
            long c, d;

            c =  IMIX0[(int)(a >>> 56)       ]
              ^  IMIX1[(int)(b >>  16) & 0xff];
            d =  IMIX0[(int)(b >>> 56)       ]
              ^  IMIX1[(int)(a >>  16) & 0xff];
            c ^= IMIX2[(int)(b >>  40) & 0xff]
              ^  IMIX3[(int) a         & 0xff];
            d ^= IMIX2[(int)(a >>  40) & 0xff]
              ^  IMIX3[(int) b         & 0xff];
            c <<= 32;
            d <<= 32;
            c ^= IMIX0[(int)(a >>  24) & 0xff]
              ^  IMIX1[(int)(a >>  48) & 0xff];
            d ^= IMIX0[(int)(b >>  24) & 0xff]
              ^  IMIX1[(int)(b >>  48) & 0xff];
            c ^= IMIX2[(int)(b >>   8) & 0xff]
              ^  IMIX3[(int)(b >>  32) & 0xff];
            d ^= IMIX2[(int)(a >>   8) & 0xff]
              ^  IMIX3[(int)(a >>  32) & 0xff];
            a = c ^ ldw[r4];
            b = d ^ ldw[r4+1];
        }

        long c, d;
        d  = IBOX[(int)(b >>> 56)       ] << 56
          ^  IBOX[(int)(a >>  16) & 0xff] << 48;
        c  = IBOX[(int)(a >>> 56)       ] << 56
          ^  IBOX[(int)(b >>  16) & 0xff] << 48;
        d ^= IBOX[(int)(a >>  40) & 0xff] << 40;
        c ^= IBOX[(int)(b >>  40) & 0xff] << 40;
        d ^= IBOX[(int) b         & 0xff] << 32;
        c ^= IBOX[(int) a         & 0xff] << 32;
        d ^= IBOX[(int)(b >>  24) & 0xff] << 24
          ^  IBOX[(int)(b >>  48) & 0xff] << 16;
        c ^= IBOX[(int)(a >>  24) & 0xff] << 24
          ^  IBOX[(int)(a >>  48) & 0xff] << 16;
        d ^= IBOX[(int)(a >>   8) & 0xff] << 8;
        c ^= IBOX[(int)(b >>   8) & 0xff] << 8
          ^  IBOX[(int)(b >>  32) & 0xff];
        d ^= IBOX[(int)(a >>  32) & 0xff];

        return new long[] {
            c ^ lw[0],
            d ^ lw[1]};
    }
}
