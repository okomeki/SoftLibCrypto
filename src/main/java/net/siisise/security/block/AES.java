package net.siisise.security.block;

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
     * Rijndael 128～256ビット 32ビット単位
     * AES 128bit固定
     */
    private final int blockLength = 128;

    private static final int[] Rcon = new int[11];

    private static final int[] sbox = new int[256];
    private static final int[] MIX0 = new int[256];
    private static final int[] MIX1 = new int[256];
    private static final int[] MIX2 = new int[256];
    private static final int[] MIX3 = new int[256];
    private static final long[] LMIX0 = new long[256];
    private static final long[] LMIX1 = new long[256];
    private static final long[] LMIX2 = new long[256];
    private static final long[] LMIX3 = new long[256];
    private static final int[] ibox = new int[256];
    private static final int[] IMIX0 = new int[256];
    private static final int[] IMIX1 = new int[256];
    private static final int[] IMIX2 = new int[256];
    private static final int[] IMIX3 = new int[256];

    /**
     * ラウンド鍵
     */
    private int[] w;
    /**
     * InvMixColumns(ラウンド鍵)
     */
    private int[] dw;

    static {
        // 2・n
        final int[] GF = new int[256];
        final int[] logGF = new int[256];
        final int[] expGF = new int[256];

        // テーブルにしてしまうといろいろ省略できる 使い捨てだが関数でもいい
        for (int i = 1; i < 256; i++) {
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

        for (int i = 0; i < 256; i++) {
            // r ガロア体の逆数変換 1回しか使わないので使い捨て
            int r = (i == 0) ? 0 : expGF[255 - logGF[i]];  // むつかしいところ
            int s = r ^ (r << 1) ^ (r << 2) ^ (r << 3) ^ (r << 4);
            s = 0x63 ^ (s ^ (s >> 8)) & 0xff; // 手抜きローテート

            sbox[i] = s;
//            sbox3[i] = s << 24; 
//            sbox2[i] = s << 16; 
//            sbox1[i] = s << 8; 
/*
            // 個別で逆も計算できるが省略
            r = (i << 1) ^ (i << 3) ^ (i << 6) ^ 0x5;
            r = (r ^ ( r >> 8)) & 0xff;
            ibox[i] = (r == 0) ? 0 : expGF[255 - logGF[r]];
/*/          
            ibox[s] = i;
//*/
            int gf2 = GF[s]; // 前段階のsboxを含める
            // 1,2,3しかないのに個別に mulとかしてはいけない
            // XOR で演算できるので 3は1と2を合成するだけ
            // sbox込み あとで XOR できるところまで計算
/*
            MIX0[i] = s * 0x00010101 ^ gf2 * 0x01000001;
            MIX1[i] = s * 0x01000101 ^ gf2 * 0x01010000;
            MIX2[i] = s * 0x01010001 ^ gf2 * 0x00010100;
            MIX3[i] = s * 0x01010100 ^ gf2 * 0x00000101;
*/
            LMIX0[i] = s * 0x00010101l ^ gf2 * 0x01000001l;
            LMIX1[i] = s * 0x01000101l ^ gf2 * 0x01010000l;
            LMIX2[i] = s * 0x01010001l ^ gf2 * 0x00010100l;
            LMIX3[i] = s * 0x01010100l ^ gf2 * 0x00000101l;

            MIX0[i] = (int) LMIX0[i];
            MIX1[i] = (int) LMIX1[i];
            MIX2[i] = (int) LMIX2[i];
            MIX3[i] = (int) LMIX3[i];

            // 同じ原理で個別の計算を省略する
            gf2 = GF[i];
            int gf4 = GF[gf2];
            int gf7 = gf4 ^ gf2 ^ i;
            int gf9x = (GF[gf4] ^ i) * 0x01010101;

            // iboxあり
            IMIX0[s] = gf9x ^ (gf7 << 24) ^  gf2        ^ (gf4 <<  8);
            IMIX1[s] = gf9x ^ (gf7 << 16) ^ (gf2 << 24) ^  gf4       ;
            IMIX2[s] = gf9x ^ (gf7 <<  8) ^ (gf2 << 16) ^ (gf4 << 24);
            IMIX3[s] = gf9x ^  gf7        ^ (gf2 <<  8) ^ (gf4 << 16);
        }

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
     * @param t
     * @return
     */
    private static int rotsubWord(int t) {
        return (sbox[t >>  16 & 0xff] << 24)
             | (sbox[t >>   8 & 0xff] << 16)
             | (sbox[t        & 0xff] << 8)
             | sbox[t >>> 24       ];
    }

    /**
     *
     * @param word
     * @return
     */
    private static int subWord(int word) {
        return (sbox[word >>> 24       ] << 24)
             | (sbox[word >>  16 & 0xff] << 16)
             | (sbox[word >>   8 & 0xff] << 8)
             | sbox[word        & 0xff];
    }

    private static final int Nb = 4;
    private int Nr4;
    
    private long[] bw;

    /**
     * 鍵.
     * AESは128bit長.
     *
     * @param key 128,192,256bit (16,24,32byte)のいずれか
     */
    @Override
    public void init(byte[] key) {

        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new SecurityException("key length");
        }

        int Nk = key.length / 4; // ぐらい
        int Nr = Nk + 6;
        Nr4 = Nr * 4;

        // ラウンド鍵の初期化 ワード列版 128*11?
        w = new int[Nb * (Nr + 1)];
        btoi(key, 0, w, Nk);
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
        
        int[] wt = new int[Nb];
        bw = new long[Nr*2];
        for (int i = 0; i < Nr; i++ ) {
            System.arraycopy(w, i * Nb, wt, 0, Nb);
            bw[i*2  ] = (((long)wt[0]) << 32) | (((long)wt[1]) & 0xffffffffl);
            bw[i*2+1] = (((long)wt[2]) << 32) | (((long)wt[3]) & 0xffffffffl);
        }
        
        // デコード用ラウンド鍵 + MixColumns
        dw = new int[w.length - 4];
        for ( int i = Nb; i < Nb * Nr; i+= Nb) {
            for (int c = 0; c < 4; c++ ) {
                int d = subWord(w[i+c]); // IMIX0はibox込みなのでiboxをsboxで消す
                dw[i+c] = IMIX0[d >>> 24]
                        ^ IMIX1[(d >> 16) & 0xff]
                        ^ IMIX2[(d >>  8) & 0xff]
                        ^ IMIX3[ d        & 0xff];
            }
        }
    }

    /**
     * 複数パラメータは持たない
     *
     * @param key
     */
    @Override
    public void init(byte[]... key) {
        init(key[0]);
    }
    
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        byte[] ret = new byte[length];
        int of = 0;
        while (length > of) {
            byte[] x = encrypt(src,offset);
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
        for ( int i = 0; i < 8; i++ ) {
            a <<= 8;
            a |= src[offset + i] & 0xff;
            b <<= 8;
            b |= src[offset+8+ i] & 0xff;
        }
        // AddRoundKey
        a ^= bw[0];
        b ^= bw[1];
        int nr = Nr4/2;
        
        for (int r = 2; r < nr; r+=2) {
            // SubBytes + ShiftRow + MixColumns
            long e, g;
            e  = LMIX0[(int)(a >>> 0x38)]
              ^  LMIX1[(int)(a >> 16) & 0xff];
            g  = LMIX0[(int)(b >>> 56)]
              ^  LMIX1[(int) b >> 16 & 0xff];
            e ^= LMIX2[(int)(b >> 40) & 0xff]
              ^  LMIX3[(int)b & 0xff];
            g ^= LMIX2[(int)(a >> 40) & 0xff]
              ^  LMIX3[(int)a & 0xff];
            e <<= 32;
            g <<= 32;
            e ^= LMIX0[(int)(a >> 24) & 0xff]
              ^  LMIX1[(int)(b >> 48) & 0xff];
            g ^= LMIX0[(int)b >> 24 & 0xff];
            g ^= LMIX1[(int)(a >> 48) & 0xff];
            e ^= LMIX2[(int)b >> 8 & 0xff]
              ^  LMIX3[(int)(a >> 32) & 0xff];
            g ^= LMIX2[(int)(a >> 8) & 0xff];
            g ^= LMIX3[(int)(b >> 32) & 0xff];

//            e |= f & 0xffffffffl;
            a = e ^ bw[r];
            b = g ^ bw[r+1];
            // AddRoundKey
//            a = e ^ w[r4++  ];
//            b = f ^ w[r4++  ];
//            c = g ^ w[r4++  ];
//            d ^=    w[r4++  ];
        }
//        s[0] = a; s[1] = b;
        

        // SubBytes + ShiftRows
        int e, f, g, d;
        e =  (sbox[(int)(a >>> 56)] << 24)
          |  (sbox[(int)(a >> 16) & 0xff] << 16);
        e |= (sbox[(int)(b >> 40) & 0xff] << 8)
          |   sbox[(int) b        & 0xff];
        f =  (sbox[(int)(a >> 24) & 0xff] << 24)
          |  (sbox[(int)(b >> 48) & 0xff] << 16);
        f |= (sbox[(int)(b >>  8) & 0xff] << 8)
          |   sbox[(int)(a >> 32) & 0xff];
        g  = (sbox[(int)(b >> 56) & 0xff] << 24)
          |  (sbox[(int)(b >> 16) & 0xff] << 16);
        g |= (sbox[(int)(a >> 40) & 0xff] << 8)
          |   sbox[(int) a        & 0xff];
        d  = (sbox[(int)(b >> 24) & 0xff] << 24)
          |  (sbox[(int)(a >> 48) & 0xff] << 16)
          |  (sbox[(int)(a >> 8) & 0xff] << 8)
          |   sbox[(int)(b >> 32) & 0xff];

        // AddRoundKey
        return itob(new int[] {
            e ^ w[Nr4] ,
            f ^ w[Nr4 + 1],
            g ^ w[Nr4 + 2],
            d ^ w[Nr4 + 3]
        });
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
    public int[] encrypt(final int[] src, int offset) {
        // AddRoundKey
        int a = src[offset] ^ w[0], b = src[++offset] ^ w[1], c = src[++offset] ^ w[2], d = src[++offset] ^ w[3];
        
        for (int r4 = 4; r4 < Nr4; r4+=4) {
            // SubBytes + ShiftRow + MixColumns
            int e, f, g;
            e  = MIX0[a >>> 24      ]
              ^  MIX1[b << 8 >>> 24 ];
            f  = MIX0[b >>> 24      ]
              ^  MIX1[c << 8 >>> 24 ];
            g  = MIX0[c >>> 24      ]
              ^  MIX1[d << 8 >>> 24 ];
            e ^= MIX2[c << 16 >>> 24]
              ^  MIX3[d       & 0xff];
            f ^= MIX2[d << 16 >>> 24]
              ^  MIX3[a       & 0xff];
            d  = MIX0[d >>> 24      ];
            g ^= MIX2[a << 16 >>> 24]
              ^  MIX3[b       & 0xff];
            d ^= MIX1[a << 8 >>> 24 ];
            d ^= MIX2[b << 16 >>> 24];
            d ^= MIX3[c       & 0xff];
            // AddRoundKey
//            a = e ^ w[r4++  ];
//            b = f ^ w[r4++  ];
//            c = g ^ w[r4++  ];
//            d ^=    w[r4++  ];
            a = e ^ w[r4  ];
            b = f ^ w[r4+1  ];
            c = g ^ w[r4+2  ];
            d ^=    w[r4+3  ];
        }

        // SubBytes + ShiftRows
        int e, f, g;
        e =  (sbox[ a >>> 24        ] << 24)
          |  (sbox[(b >>  16) & 0xff] << 16);
        e |= (sbox[(c >>   8) & 0xff] <<  8)
          |   sbox[ d         & 0xff];
        f =  (sbox[ b >>> 24        ] << 24)
          |  (sbox[(c >>  16) & 0xff] << 16);
        f |= (sbox[(d >>   8) & 0xff] <<  8)
          |   sbox[ a         & 0xff];
        g  = (sbox[ c >>> 24        ] << 24)
          |  (sbox[(d >>  16) & 0xff] << 16);
        g |= (sbox[(a >>   8) & 0xff] <<  8)
          |   sbox[ b         & 0xff];
        d  = (sbox[ d >>> 24        ] << 24)
          |  (sbox[(a >>  16) & 0xff] << 16)
          |  (sbox[(b >>   8) & 0xff] <<  8)
          |   sbox[ c         & 0xff];

        // AddRoundKey
        return new int[] {
            e ^ w[Nr4] ,
            f ^ w[Nr4 + 1],
            g ^ w[Nr4 + 2],
            d ^ w[Nr4 + 3]
        };
    }

    @Override
    public int[] decrypt(final int[] src, final int offset) {
        int a,b,c,d;
        a = w[Nr4 + 0] ^ src[offset + 0];
        b = w[Nr4 + 1] ^ src[offset + 1];
        c = w[Nr4 + 2] ^ src[offset + 2];
        d = w[Nr4 + 3] ^ src[offset + 3];

        for (int r4 = Nr4 - 4; r4 > 0; r4-=4) {
            int e, f, g;
        
            e = IMIX0[a >>> 24       ]
                 ^ IMIX1[d << 8 >>> 24]
                 ^ IMIX2[c << 16 >>> 24]
                 ^ IMIX3[b        & 0xff];
            f = IMIX0[b >>> 24       ]
                 ^ IMIX1[a >>  16 & 0xff]
                 ^ IMIX2[d >>   8 & 0xff]
                 ^ IMIX3[c        & 0xff];
            g = IMIX0[c >>> 24       ]
                 ^ IMIX1[b >>  16 & 0xff]
                 ^ IMIX2[a >>   8 & 0xff]
                 ^ IMIX3[d        & 0xff];
            d = IMIX0[d >>> 24       ]
                 ^ IMIX1[c >>  16 & 0xff]
                 ^ IMIX2[b >>   8 & 0xff]
                 ^ IMIX3[a        & 0xff]
                 ^  dw[r4 + 3];
            a = e ^ dw[r4];
            b = f ^ dw[r4 + 1];
            c = g ^ dw[r4 + 2];
        }
        int e, f, g, h;
        e  = ibox[a >>> 24       ] << 24
          ^  ibox[d >>  16 & 0xff] << 16;
        e ^= ibox[c >>   8 & 0xff] << 8;
        e |= ibox[b        & 0xff];
        f  = ibox[b >>> 24       ] << 24
          ^  ibox[a >>  16 & 0xff] << 16;
        f ^= ibox[d >>   8 & 0xff] << 8
          ^  ibox[c        & 0xff];
        g  = ibox[c >>> 24       ] << 24
          ^  ibox[b >>  16 & 0xff] << 16;
        g ^= ibox[a >>   8 & 0xff] << 8;
        g ^= ibox[d        & 0xff];
        h  = ibox[d >>> 24       ] << 24
          ^  ibox[c >>  16 & 0xff] << 16;
        h ^= ibox[b >>   8 & 0xff] << 8;
        h ^= ibox[a        & 0xff];

        return new int[] {
            e ^ w[0],
            f ^ w[1],
            g ^ w[2],
            h ^ w[3]};
    }
}
