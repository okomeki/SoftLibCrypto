package net.siisise.security.block;

/**
 * Adbanced Encryption Standard.
 * FIPS 197
 * Rijndael という名称.
 *
 * RoundKey参考
 * https://qiita.com/tobira-code/items/152befa86bd515f67241
 * MixColumns
 * https://tex2e.github.io/blog/crypto/aes-mix-columns
 */
public class AES extends OneBlock {

    /**
     * Rijndael 128～256ビット 32ビット単位
     * AES 128bit固定
     */
    int blockLength = 128;

//    private static final int[] GF3 = new int[256];
    // 9・n
    private static final int[] GFN = new int[11];
    
    private static final int[] sbox = new int[256];
    private static final int[] mix0 = new int[256];
    private static final int[] mix1 = new int[256];
    private static final int[] mix2 = new int[256];
    private static final int[] mix3 = new int[256];
    private static final int[] ibox = new int[256];
    private static final int[] imix0 = new int[256];
    private static final int[] imix1 = new int[256];
    private static final int[] imix2 = new int[256];
    private static final int[] imix3 = new int[256];

    /**
     * ラウンド鍵
     */
    private int[] w;

    static {
        // 2・n
        int[] GF = new int[256];
        int[] logGF = new int[256];
        int[] expGF = new int[256];

        for (int i = 1; i < 256; i++) {
            GF[i] = (i << 1) ^ ((i >> 7) * 0x11b);
        }

        // sboxつくる
        // https://tociyuki.hatenablog.jp/entry/20160427/1461721356
        int n = 1;
        for (int e = 0; e < 255; e++) {
            logGF[n] = e;
            expGF[e] = n;
            n ^= GF[n]; // 3・n
        }
        logGF[0] = 0;
        expGF[255] = expGF[0];

        for (int i = 0; i < 256; i++) {
            int q = (i == 0) ? 0 : expGF[255 - logGF[i]];  // むつかしいところ
            int d = q ^ (q << 1) ^ (q << 2) ^ (q << 3) ^ (q << 4) ^ 0x63;
            d = (d ^ (d >> 8)) & 0xff; // 手抜きローテート

            sbox[i] = d;
            ibox[d] = i;

            int gf = GF[d];
            // sbox込み あとで XOR できるところまで計算
            mix0[i] = d * 0x00010101 ^ (gf * 0x01000001);
            mix1[i] = d * 0x01000101 ^ (gf * 0x01010000);
            mix2[i] = d * 0x01010001 ^ (gf * 0x00010100);
            mix3[i] = d * 0x01010100 ^ (gf * 0x00000101);
//System.out.println("mix"+i+" "+Integer.toHexString(mix0[i]));
            gf = GF[i];
            int gf4 = GF[gf];
            int gf7 = gf4 ^ gf ^ i;
            int gf9x = (GF[gf4] ^ i) * 0x01010101;

            // iboxなし
            imix0[i] = gf9x ^ (gf7 << 24) ^ (gf      ) ^ (gf4 <<  8);
            imix1[i] = gf9x ^ (gf7 << 16) ^ (gf << 24) ^ (gf4      );
            imix2[i] = gf9x ^ (gf7 <<  8) ^ (gf << 16) ^ (gf4 << 24);
            imix3[i] = gf9x ^  gf7        ^ (gf <<  8) ^ (gf4 << 16);
        }

        n = 1;
        for (int i = 1; i < 11; i++) { // 使う範囲で生成
            GFN[i] = n << 24;
            n = GF[n];
        }
    }

    /**
     * Sec. 5.2.
     * @param s
     * @param w 
     */
    private void addRoundKey(int[] s, int round) {
        round *=4;
        for (int c = 0; c < 4; c++) {
            s[c] ^= w[round+c];
        }
    }

    private static void subBytes(int[] s) {
        for ( int i = 0; i < 4; i++ ) {
            int d = s[i];
            s[i] = (sbox[ d >>> 24        ] << 24)
                 | (sbox[(d >>  16) & 0xff] << 16)
                 | (sbox[(d >>   8) & 0xff] <<  8)
                 |  sbox[ d         & 0xff];
        }
    }

    /**
     * MixColumns.
     * あらかじめ計算しておけるらしい。
     */
    private static void mixColumns(int[] s) {
        for ( int c = 0; c < 4; c++ ) {
            int d = s[c];
            s[c] = mix0[ d >>> 24        ]
                 ^ mix1[(d >>  16) & 0xff]
                 ^ mix2[(d >>   8) & 0xff]
                 ^ mix3[ d         & 0xff];
        }
    }

    /**
     * SubBytes() の逆.
     */
    private static void invSubBytes(int[] s) {
        for ( int i = 0; i < 4; i++ ) {
            int d = s[i];
            s[i] = (ibox[ d >>> 24        ] << 24)
                 | (ibox[(d >>  16) & 0xff] << 16)
                 | (ibox[(d >>   8) & 0xff] <<  8)
                 |  ibox[ d         & 0xff];
        }
    }

    private static void shiftRows(int[] s) {
        int a = s[0], b = s[1], c = s[2], d = s[3];
        s[0] = (a & 0xff000000) | (b & 0xff0000) | (c & 0xff00) | (d & 0xff);
        s[1] = (b & 0xff000000) | (c & 0xff0000) | (d & 0xff00) | (a & 0xff);
        s[2] = (c & 0xff000000) | (d & 0xff0000) | (a & 0xff00) | (b & 0xff);
        s[3] = (d & 0xff000000) | (a & 0xff0000) | (b & 0xff00) | (c & 0xff);
    }

    /**
     * ShiftRows() の逆.
     */
    private static void invShiftRows(int[] s) {
        int a = s[0], b = s[1], c = s[2], d = s[3];
        s[0] = (a & 0xff000000) | (d & 0xff0000) | (c & 0xff00) | (b & 0xff);
        s[1] = (b & 0xff000000) | (a & 0xff0000) | (d & 0xff00) | (c & 0xff);
        s[2] = (c & 0xff000000) | (b & 0xff0000) | (a & 0xff00) | (d & 0xff);
        s[3] = (d & 0xff000000) | (c & 0xff0000) | (b & 0xff00) | (a & 0xff);
    }

    /**
     * MixColumns() の逆.
     */
    private void invMixColumns(int[] s) {
        for ( int c = 0; c < 4; c++ ) {
            int d = s[c];
            s[c] = imix0[ d >>> 24        ]
                 ^ imix1[(d >>  16) & 0xff]
                 ^ imix2[(d >>   8) & 0xff]
                 ^ imix3[ d         & 0xff];
        }
    }

    @Override
    public int getBlockLength() {
        return blockLength;
    }

    private static int rotsubWord(int t) {
        return (sbox[(t >>  16) & 0xff] << 24)
             | (sbox[(t >>   8) & 0xff] << 16)
             | (sbox[ t         & 0xff] <<  8)
             |  sbox[ t >>> 24        ];
    }

    private static int subWord(int word) {
        return (sbox[ word >>> 24        ] << 24)
             | (sbox[(word >>  16) & 0xff] << 16)
             | (sbox[(word >>   8) & 0xff] <<  8)
             |  sbox[ word         & 0xff];
    }
    
    private static final int Nb = 4;
    private int Nr;
    
    /**
     * 鍵.
     * AESは128bit長.
     * 
     * @param key 128,192,256bit (16,24,32byte)のいずれか
     */
    @Override
    public void init(byte[] key) {
        
        if ( key.length != 16 && key.length != 24 && key.length != 32 ) {
            throw new SecurityException("key length");
        }
        
        int Nk = key.length / 4; // ぐらい
        blockLength = key.length * 8;
        Nr = Nk + 6;
        
        // ラウンドキーの初期化 ワード列版 128*11?
        w = new int[Nb * (Nr+1)];
        btoi(key,0, w, 0, Nk);
        int temp;
        for (int i = Nk; i < Nb * (Nr+1); i++) {
            temp = w[i-1];
            if ( i % Nk == 0) {
                temp = rotsubWord(temp) ^ GFN[i/Nk];
            } else if (Nk > 6 && i % Nk == 4) {
                temp = subWord(temp);
            }
            w[i] = w[i-Nk] ^ temp;
        }
    }
    
    private static void btoi(byte[] src, int offset, int[] dst, int doffset, int length) {
        for ( int i = 0; i < length*4; i+=4 ) {
            int t = offset + i;
            dst[doffset + i/4] =
                      ((src[t  ] & 0xff) << 24)
                    | ((src[t+1] & 0xff) << 16)
                    | ((src[t+2] & 0xff) <<  8)
                    |  (src[t+3] & 0xff);
        }
    }
    
    private static byte[] itob(int[] src) {
        byte[] ss = new byte[16];
        for ( int i = 0; i < 4; i++ ) {
            ss[i*4  ] = (byte) (src[i] >> 24);
            ss[i*4+1] = (byte) (src[i] >> 16);
            ss[i*4+2] = (byte) (src[i] >>  8);
            ss[i*4+3] = (byte)  src[i]       ;
        }
        return ss;
    }

    /** 使わない */
    @Override
    public void init(byte[] key, byte[] iv) {
        throw new SecurityException();
    }

    /**
     * tmp[r,c] = in[r+4c]
 w0 = tmp[0,0] tmp[1,0] tmp[2,0] tmp[3,0]
 w3
     * @param src
     * @param offset
     */    
    @Override
    public byte[] encrypt(final byte[] src, final int offset) {
        int[] s = new int[4];
        btoi(src,offset,s,0,4);
        addRoundKey(s, 0);
        for ( int r = 1; r < Nr; r++ ) {
            shiftRows(s);
            //subBytes(tmp);
            mixColumns(s);
            addRoundKey(s, r);
        }
        subBytes(s);
        shiftRows(s);
        addRoundKey(s, Nr);

        return itob(s);

    }

    @Override
    public byte[] decrypt(final byte[] src, final int offset) {
        
        int[] s = new int[4];
        btoi(src,offset,s,0,4);
        addRoundKey(s, Nr);
        invShiftRows(s);
        invSubBytes(s);
        for (int r = Nr-1; r >= 1; r-- ) {
            addRoundKey(s, r);
            invMixColumns(s);
            invShiftRows(s);
            invSubBytes(s);
        }
        addRoundKey(s, 0);
        
        return itob(s);
    }
}
