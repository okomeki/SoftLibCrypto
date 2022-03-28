package net.siisise.security.block;

/**
 * Data Encryption Standard.
 * FIPS PUB 46-3.
 * ANSI X3.92
 * NIST SP 800-67.
 * ISO/IEC 18033-3
 * 56bit暗号 上位1 下位64
 * 内部処理を0ベースにしたりいろいろ最適化済み.
 *
 * @deprecated AES
 */
public class DES extends OneBlock {

    /**
     * DESのブロック長.
     * 64bit っぽい56bit
     *
     * @return 64
     */
    @Override
    public int getBlockLength() {
        return 64;
    }

    /**
     * 変な並びをあらかじめ解除したS列.
     */
    private static final byte[][] S = {
        {14, 0, 4, 15, 13, 7, 1, 4, 2, 14, 15, 2, 11, 13, 8, 1, 3, 10, 10, 6, 6, 12, 12, 11, 5, 9, 9, 5, 0, 3, 7, 8,
            4, 15, 1, 12, 14, 8, 8, 2, 13, 4, 6, 9, 2, 1, 11, 7, 15, 5, 12, 11, 9, 3, 7, 14, 3, 10, 10, 0, 5, 6, 0, 13},
        {15, 3, 1, 13, 8, 4, 14, 7, 6, 15, 11, 2, 3, 8, 4, 14, 9, 12, 7, 0, 2, 1, 13, 10, 12, 6, 0, 9, 5, 11, 10, 5,
            0, 13, 14, 8, 7, 10, 11, 1, 10, 3, 4, 15, 13, 4, 1, 2, 5, 11, 8, 6, 12, 7, 6, 12, 9, 0, 3, 5, 2, 14, 15, 9},
        {10, 13, 0, 7, 9, 0, 14, 9, 6, 3, 3, 4, 15, 6, 5, 10, 1, 2, 13, 8, 12, 5, 7, 14, 11, 12, 4, 11, 2, 15, 8, 1,
            13, 1, 6, 10, 4, 13, 9, 0, 8, 6, 15, 9, 3, 8, 0, 7, 11, 4, 1, 15, 2, 14, 12, 3, 5, 11, 10, 5, 14, 2, 7, 12},
        {7, 13, 13, 8, 14, 11, 3, 5, 0, 6, 6, 15, 9, 0, 10, 3, 1, 4, 2, 7, 8, 2, 5, 12, 11, 1, 12, 10, 4, 14, 15, 9,
            10, 3, 6, 15, 9, 0, 0, 6, 12, 10, 11, 1, 7, 13, 13, 8, 15, 9, 1, 4, 3, 5, 14, 11, 5, 12, 2, 7, 8, 2, 4, 14},
        {2, 14, 12, 11, 4, 2, 1, 12, 7, 4, 10, 7, 11, 13, 6, 1, 8, 5, 5, 0, 3, 15, 15, 10, 13, 3, 0, 9, 14, 8, 9, 6,
            4, 11, 2, 8, 1, 12, 11, 7, 10, 1, 13, 14, 7, 2, 8, 13, 15, 6, 9, 15, 12, 0, 5, 9, 6, 10, 3, 4, 0, 5, 14, 3},
        {12, 10, 1, 15, 10, 4, 15, 2, 9, 7, 2, 12, 6, 9, 8, 5, 0, 6, 13, 1, 3, 13, 4, 14, 14, 0, 7, 11, 5, 3, 11, 8,
            9, 4, 14, 3, 15, 2, 5, 12, 2, 9, 8, 5, 12, 15, 3, 10, 7, 11, 0, 14, 4, 1, 10, 7, 1, 6, 13, 0, 11, 8, 6, 13},
        {4, 13, 11, 0, 2, 11, 14, 7, 15, 4, 0, 9, 8, 1, 13, 10, 3, 14, 12, 3, 9, 5, 7, 12, 5, 2, 10, 15, 6, 8, 1, 6,
            1, 6, 4, 11, 11, 13, 13, 8, 12, 1, 3, 4, 7, 10, 14, 7, 10, 9, 15, 5, 6, 0, 8, 15, 0, 14, 5, 2, 9, 3, 2, 12},
        {13, 1, 2, 15, 8, 13, 4, 8, 6, 10, 15, 3, 11, 7, 1, 4, 10, 12, 9, 5, 3, 6, 14, 11, 5, 0, 0, 14, 12, 9, 7, 2,
            7, 2, 11, 1, 4, 14, 1, 7, 9, 4, 12, 10, 14, 8, 2, 13, 0, 15, 6, 12, 10, 9, 13, 0, 15, 3, 3, 5, 5, 6, 8, 11}
    };

    private static final int[] P = {
        15, 6, 19, 20,
        28, 11, 27, 16,
        0, 14, 22, 25,
        4, 17, 30, 9,
        1, 7, 23, 13,
        31, 26, 2, 8,
        18, 12, 29, 5,
        21, 10, 3, 24
    };

    /**
     * P処理済みのSテーブル 2KBくらい
     */
    private static final int[][] SP = new int[8][64];

    static {
        // S&P to SP
        for ( int i = 0; i < 32; i++ ) {
            int n = P[i];
            int n4 = n / 4; // S列を特定
            int np = 1 << (3 - (n % 4)); // 該当S出力ビットを特定
            int t = 1 << (31 - i); // S出力からP出力の変換コードを作成
            for ( int j = 0; j < 64; j++ ) { // 該当個所に書き込み
                SP[n4][j] |= ((S[n4][j] & np) != 0) ? t : 0;
            }
        }

    }

    public DES() {
    }

    private byte[][] ks = new byte[16][];

    static void parityCheck(byte[] key) {
        if (key == null || key.length != 8) {
            throw new SecurityException();
        }
        int p = 0;
        for (int i = 0; i < 8; i++) {
            for (int b = 0; b < 8; b++) {
                p ^= ((key[i] >>> b) & 1) << i;
            }
        }
        if (p != 0) {
            throw new SecurityException("ぱりてー");
        }
    }

    /*
     * ひとつ引いた値
     */
/*    private static final int PC1[] = {
        56, 48, 40, 32, 24, 16,  8,
         0, 57, 49, 41, 33, 25, 17,
         9,  1, 58, 50, 42, 34, 26,
        18, 10,  2, 59, 51, 43, 35,

        62, 54, 46, 38, 30, 22, 14,
         6, 61, 53, 45, 37, 29, 21,
        13,  5, 60, 52, 44, 36, 28,
        20, 12,  4, 27, 19, 11,  3
    };
*/
    /**
     * 1つ引いて下位3ビットを反転したもの
     */
    private static final int PC1[] = {
        63, 55, 47, 39, 31, 23, 15,
         7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 60, 52, 44, 36,

        57, 49, 41, 33, 25, 17,  9,
         1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 28, 20, 12,  4
    };

    /**
     *
     * @param key 7bit 8バイト
     * @return 28*2bit
     */
    private static int[] pc1(byte[] key) {
        int[] cd = new int[2];
        for (int i = 0; i < 2; i++) {
            for (int j = 0; j < 28; j++) {
                int s = PC1[i * 28 + j];
                cd[i] <<= 1;
                cd[i] |= ((key[s / 8] & 0xff) >>> (s % 8)) & 1;
            }
        }
        return cd;
    }

    /**
     * ひとつ減らした値
     */
    private static final int PC2[] = {
        13, 16, 10, 23,  0,  4,
         2, 27, 14,  5, 20,  9,
        22, 18, 11,  3, 25,  7,
        15,  6, 26, 19, 12,  1,
        40, 51, 30, 36, 46, 54,
        29, 39, 50, 44, 32, 47,
        43, 48, 38, 55, 33, 52,
        45, 41, 49, 35, 28, 31
    };

    /**
     * 56bit から 48bitのサブ鍵生成
     *
     * @param cd 28bit x2
     * @return
     */
    private static byte[] pc2(int[] cd) {
        byte[] kn = new byte[8];
        for (int i = 0; i < 8; i++) {
            for (int j = 0; j < 6; j++) {
                int s = PC2[i * 6 + j];
                kn[i] <<= 1;
                kn[i] |= (cd[s / 28] >>> (27 - (s % 28))) & 1;
            }
        }
//        cd[0] = 0; cd[1] = 0; // 念入りな掃除?
        return kn;
    }

    /**
     * シフト量をあらかじめ計算したもの.
     */
    private static final int[] shifts = {1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 0};

    /**
     * ラウンドキーを作る.
     * 56bitから48bitへ
     *
     * @param i
     * @return
     */
    private byte[] ks(int[] keys0, int i) {
        int[] k = new int[2];

        int s = shifts[i];
        k[0] = ((keys0[0] << s) | (keys0[0] >>> (28 - s))) & 0xfffffff;
        k[1] = ((keys0[1] << s) | (keys0[1] >>> (28 - s))) & 0xfffffff;
        return pc2(k);
    }

    @Override
    public void init(byte[] key) {
        //parityCheck(key);
        int[] keys0 = pc1(key);
        for (int i = 0; i < 16; i++) {
            ks[i] = ks(keys0, i);
        }
    }

    @Override
    public void init(byte[]... key) {
        throw new SecurityException("さぽーとしてない");
    }

    final byte[] e = new byte[8];

    private void e(int r) {
        e[0] = (byte) ((r << 5) | (r >>> 27));
        e[1] = (byte) (r >>> 23);
        e[2] = (byte) (r >>> 19);
        e[3] = (byte) (r >>> 15);
        e[4] = (byte) (r >>> 11);
        e[5] = (byte) (r >>> 7);
        e[6] = (byte) (r >>> 3);
        e[7] = (byte) ((r << 1) | (r >>> 31));
//        return e;
    }

    /**
     * 間違えてもわかりにくい.
     *
     * @param r 32bitデータ
     * @param kn 鍵番号
     * @return 32bitハッシュ系データ
     */
    private int f(int r, int kn) {
        e(r); // 6x8bit 48ビットに増やす
        byte[] k1 = ks[kn];

        int re = 0;
        for (int i = 0; i < 8; i++) {
            // S、Pをまとめた処理
            re |= SP[i][(e[i] ^ k1[i]) & 0x3f];
        }
        return re;
    }

    private static final int[] ip1 = {6, 4, 2, 0, 7, 5, 3, 1};

    /**
     * IP処理
     *
     * @param src
     * @param offset
     * @return
     */
    private static int[] ip(byte[] src, int offset) {
        int[] lr = new int[2];
        for (int n = 0; n < 8; n++) {
            int n4 = n / 4;
            for (int i = 7; i >= 0; i--) {
                lr[n4] <<= 1;
                lr[n4] |= (src[offset + i] >>> ip1[n]) & 1;
            }
        }
        return lr;
    }

//    private static final int[] ipr1 = {4, 0, 5, 1, 6, 2, 7, 3};

    /**
     * IPの逆.
     * intからバイト列にする過程を省略してみる
     *
     * @param src
     * @return
     */
    private static byte[] ip_1(int[] src) {
        byte[] x = new byte[8];

        for (int n = 0; n < 8; n++) {
            int d = (src[(~n) & 1] >>> (24 - (n / 2) * 8));
            for (int i = 7; i >= 0; i--) {
                x[i] <<= 1;
                x[i] |= (d >>> i) & 1;
            }
        }
        return x;
    }

    /**
     * 暗号化.
     * @param src 64bit
     * @return
     */
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        int[] lr = ip(src, offset);
        int t;

        for (int i = 0; i < 15; i++) {
            t = lr[1];
            lr[1] = lr[0] ^ f(t, i);
            lr[0] = t;
        }
        lr[0] ^= f(lr[1], 15);

        return ip_1(lr);
    }

    /**
     * 復号化.
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        int[] lr = ip(src, offset);
        int t;

        for (int i = 15; i >= 1; i--) {
            t = lr[1];
            lr[1] = lr[0] ^ f(t, i);
            lr[0] = t;
        }
        lr[0] ^= f(lr[1], 0);

        return ip_1(lr);
    }

}
