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
public class AESLong extends OneBlock {

    /**
     * Rijndael 128～256ビット 32ビット単位
     * AESLong 128bit固定
     */
    private final int blockLength = 128;

    private static final int[] Rcon = new int[11];

    private static final int[] sbox = new int[256];
    private static final int[] MIX0 = new int[256];
    private static final int[] MIX1 = new int[256];
    private static final int[] MIX2 = new int[256];
    private static final int[] MIX3 = new int[256];
    private static final int[] ibox = new int[256];
    private static final int[] IMIX0 = new int[256];
    private static final int[] IMIX1 = new int[256];
    private static final int[] IMIX2 = new int[256];
    private static final int[] IMIX3 = new int[256];

    /**
     * ラウンド鍵
     */
    private int[] w;

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
/*
            // 個別で逆も計算できるが省略
            r = (i << 1) ^ (i << 3) ^ (i << 6) ^ 0x5;
            r = (r ^ ( r >> 8)) & 0xff;
            ibox[i] = (r == 0) ? 0 : expGF[255 - logGF[r]];
/*/          
            ibox[s] = i;
//*/
            int gf = GF[s]; // 前段階のsboxを含める
            // 1,2,3しかないのに個別に mulとかしてはいけない
            // XOR で演算できるので 3は1と2を合成するだけ
            // sbox込み あとで XOR できるところまで計算
            MIX0[i] = s * 0x00010101 ^ gf * 0x01000001;
            MIX1[i] = s * 0x01000101 ^ gf * 0x01010000;
            MIX2[i] = s * 0x01010001 ^ gf * 0x00010100;
            MIX3[i] = s * 0x01010100 ^ gf * 0x00000101;

            // 同じ原理で個別の計算を省略する
            gf = GF[i];
            int gf4 = GF[gf];
            int gf7 = gf4 ^ gf ^ i;
            int gf9x = (GF[gf4] ^ i) * 0x01010101;

            // iboxなし
            IMIX0[i] = gf9x ^ (gf7 << 24) ^  gf        ^ (gf4 <<  8);
            IMIX1[i] = gf9x ^ (gf7 << 16) ^ (gf << 24) ^  gf4       ;
            IMIX2[i] = gf9x ^ (gf7 <<  8) ^ (gf << 16) ^ (gf4 << 24);
            IMIX3[i] = gf9x ^  gf7        ^ (gf <<  8) ^ (gf4 << 16);
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
        return sbox[t >>  16 & 0xff] << 24
             | sbox[t >>   8 & 0xff] << 16
             | sbox[t        & 0xff] <<  8
             | sbox[t >>> 24       ];
    }

    /**
     *
     * @param word
     * @return
     */
    private static int subWord(int word) {
        return sbox[word >>> 24       ] << 24
             | sbox[word >>  16 & 0xff] << 16
             | sbox[word >>   8 & 0xff] <<  8
             | sbox[word        & 0xff];
    }

    private static final int Nb = 4;
    private int Nr4;

    /**
     * 鍵.
     * AESは128bit長.
     *
     * @param key 128,192,256bit (16,24,32byte)のいずれか
     */
    public void init(byte[] key) {

        if (key.length != 16 && key.length != 24 && key.length != 32) {
            throw new SecurityException("key length");
        }

        int Nk = key.length / 4; // ぐらい
        int Nr = Nk + 6;
        Nr4 = Nr * 4;

        // ラウンドキーの初期化 ワード列版 128*11?
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
    }
/*
    private static void btoi(final byte[] src, int offset, int[] dst, int length) {
        for (int i = 0; i < length * 4; i += 4) {
            int t = offset + i;
            dst[i / 4]
                    = ( src[t    ]         << 24)
                    | ((src[t + 1] & 0xff) << 16)
                    | ((src[t + 2] & 0xff) <<  8)
                    |  (src[t + 3] & 0xff);
        }
    }

    private static byte[] itob(final int[] src) {
        byte[] ss = new byte[16];
        for (int i = 0; i < 4; i++) {
            int l = i*4;
            ss[l    ] = (byte) (src[i] >> 24);
            ss[l + 1] = (byte) (src[i] >> 16);
            ss[l + 2] = (byte) (src[i] >>  8);
            ss[l + 3] = (byte)  src[i]       ;
        }
        return ss;
    }
*/
    /**
     * 複数パラメータは持たない
     *
     * @param key
     */
    @Override
    public void init(byte[]... key) {
        throw new SecurityException();
    }
    
    /**
     * Sec. 5.2.
     *
     * @param s
     * @param round
     */
    private void addRoundKey(int[] s, int round) {
        for (int c = 0; c < 4; c++) {
            s[c] ^= w[round + c];
        }
    }

    private void addRoundKey(byte[] src, int offset, int[] s, int round) {
//        round *= 4;
        System.arraycopy(w, round, s, 0, 4);
        for ( int i = 0; i < 4; i++ ) {
            int t = offset + i*4;
            s[i] ^= ( ((src[t  ] & 0xff) << 24)
                    | ((src[t+1] & 0xff) << 16)
                    | ((src[t+2] & 0xff) <<  8)
                    |  (src[t+3] & 0xff));
        }
    }

    /**
     * ShiftRows() の逆 + SubBytes() の逆.
     */
    private static void invShiftSub(int[] s) {
        int a = s[0], b = s[1], c = s[2], d = s[3];
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

        s[0] = e;
        s[1] = f;
        s[2] = g;
        s[3] = h;
    }

    /**
     * MixColumns() の逆.
     */
    private static void invMixColumns(int[] s) {
        for (int c = 0; c < 4; c++) {
            int d = s[c];
            s[c] = IMIX0[d >>> 24       ]
                 ^ IMIX1[d >>  16 & 0xff]
                 ^ IMIX2[d >>   8 & 0xff]
                 ^ IMIX3[d        & 0xff];
        }
    }

    /**
     * AESLong エンコード
 AMD Ryzen 5 2600X で AESLong/CBCで 950Mbpsを超える
     *
     * @param src source 16byte
     * @param offset 先頭位置
     */
    @Override
    public byte[] encrypt(final byte[] src, final int offset) {
        int t = offset;
        // AddRoundKey
        int a = w[0], b = w[1], c = w[2], d = w[3];
        for (int i = 0; i < 4; i++) {
            int n = 24 - 8 * i;
            a ^= ((src[t     ] & 0xff) << n);
            b ^= ((src[t +  4] & 0xff) << n);
            c ^= ((src[t +  8] & 0xff) << n);
            d ^= ((src[t + 12] & 0xff) << n);
            t++;
        }
        
        // SubBytes + ShiftRow + MixColumns
        for (int r4 = 4; r4 < Nr4; r4 += 4) {
            int e, f, g;
            e  = MIX0[ a >>> 24        ]
              ^  MIX1[(b >>  16) & 0xff];
            f  = MIX0[ b >>> 24        ]
              ^  MIX1[(c >>  16) & 0xff];
            g  = MIX0[ c >>> 24        ]
              ^  MIX1[(d >>  16) & 0xff];
            e ^= MIX2[(c >>   8) & 0xff]
              ^  MIX3[ d         & 0xff];
            f ^= MIX2[(d >>   8) & 0xff]
              ^  MIX3[ a         & 0xff];
            d  = MIX0[ d >>> 24        ];
            g ^= MIX2[(a >>   8) & 0xff]
              ^  MIX3[ b         & 0xff];
            d ^= MIX1[(a >>  16) & 0xff];
            d ^= MIX2[(b >>   8) & 0xff];
            d ^= MIX3[ c         & 0xff];
            // AddRoundKey
            a = e ^ w[r4    ];
            b = f ^ w[r4 + 1];
            c = g ^ w[r4 + 2];
            d ^=    w[r4 + 3];
        }

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
        return itob( new int[] {
            e ^ w[Nr4] ,
            f ^ w[Nr4 + 1],
            g ^ w[Nr4 + 2],
            d ^ w[Nr4 + 3]
        } );
    }

    @Override
    public byte[] decrypt(final byte[] src, final int offset) {

        int[] s = new int[4];
        addRoundKey(src, offset, s, Nr4);
        invShiftSub(s);
        for (int r4 = Nr4 - 4; r4 >= 4; r4-=4) {
            addRoundKey(s, r4);
            invMixColumns(s);
            invShiftSub(s);
        }
        addRoundKey(s, 0);

        return itob(s);
    }
}
