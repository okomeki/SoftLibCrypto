package net.siisise.security.digest;

import java.util.Arrays;
import net.siisise.security.io.BlockOutputStream;

/**
 * Keccak-f[1600].
 * SHA-3のもと
 * cは2倍にしていいのか謎
 *
 * Keccak-f[b] {25, 50, 100, 200, 400, 800, 1600} のうち b = 1600 のもの
 * 固定値
 * l = 6; w = 64; b = 5*5*w = 1600
 * 可変値
 * c: capacity SHA-3では2*d, d: 出力ビット長, pad頭
 */
public class Keccak extends BlockMessageDigest {

    // 固定値
    private static final int l = 6;
    private static final int w = 1 << l;
    // 固定箱
    private final long[] a = new long[5 * 5];

    // 出力ビット長
    private int d;

    // 入出力分割ビット数?
    private int r;
    private int R;

    static final long[] RC = new long[24];

    static {
        for (int ir = 0; ir < 24; ir++) {
            for (int j = 0; j <= l; j++) { // l = 6
                // little endian
                RC[ir] |= rc(j + 7 * ir) ? (1l << ((1 << j) - 1)) : 0;
            }
        }
    }

    private byte padstart;

    /**
     * Keccak[c](N,d).
     * c = 2*d の SHA-3相当
     *
     * @param d 出力ビット長 c=2*d
     */
    public Keccak(int d) {
        this(2 * d, d);
    }

    /**
     * 5.2. Specification of KECCAK[c].
     *
     * Keccak[c](N,d)
     * N 入力
     *
     * @param c キャパシティ b まで
     * @param d 出力ビット長 b まで
     */
    public Keccak(int c, int d) {
        this("Keccak[" + c + "](N," + d + ")", c, d, (byte) 0x01);
    }

    /**
     *
     * Keccak[c](N,d)
     * l = 6
     * SPONGE[KECCAK-p[1600,12+2l],pad10*1,1600-c]
     * N 入力
     *
     * @param name
     * @param c キャパシティ 2*d か d か固定
     * @param d 出力長
     * @param suffix Keccakと独自のをまとめた値 頭ビットは下位
     */
    protected Keccak(String name, int c, int d, byte suffix) {
        super(name + d);
        this.d = d;
        r = 5 * 5 * w - c; // 1600-c 448,512,768,1024 
        R = r / w;
        padstart = suffix;
        engineReset();
    }

    @Override
    protected int engineGetDigestLength() {
        return d / 8;
    }

    @Override
    public int getBitBlockLength() {
        return r;
    }

    @Override
    protected void engineReset() {
        pac = new BlockOutputStream(this);
        length = 0;
        Arrays.fill(a, 0l);
    }

    // little endian
    private static final long ROTL(final long x, final long n) {
        // d = d % w;
        return (x >>> (w - n)) | (x << n);
    }

    /**
     * Algorithm 5.
     * 事前計算可能
     * bitなので big endian で計算している
     */
    static boolean rc(int t) {
        if (t % 255 == 0) {
            return true;
        }
        int R = 0x80;
        for (int i = 1; i <= t % 255; i++) {
            R = (R & 0xe3) | ((R & 0x1c) ^ ((R & 1) * 0x11c));
            R >>>= 1;
        }
        return (R & 0x80) != 0;
    }

//    static final int[] rr = {0,300,171,21,78,28,276,3,45,253,1,6,153,136,210,91,36,10,15,120,190,55,231,105,66};
    static final int[] rr = {0, 44, 43, 21, 14, 28, 20, 3, 45, 61, 1, 6, 25, 8, 18, 27, 36, 10, 15, 56, 62, 55, 39, 41, 2};

    /**
     *
     * @param a
     */
    private void keccak_f(long[] a) {
        long[] ad = new long[25];

        for (int ir = 0; ir < 12 + 2 * l; ir++) {
            // 3.2.1 Θ
            // Step 1.
            for (int x = 0; x < 5; x++) {
                ad[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
            }
            // Step 2.
            for (int x = 5; x < 10; x++) {
                ad[x] = ad[(x + 4) % 5] ^ ROTL(ad[(x + 1) % 5], 1);
            }
            // Step 3.
            for (int b = 0; b < 25; b++) {
                a[b] ^= ad[5 + b % 5];
            }
            // 3.2.2. ρ
            // 3.2.3 π
            for (int y = 0; y < 5; y++) {
                for (int x = 0; x < 5; x++) {
                    ad[x + y * 5] = ROTL(a[(y * 3 + x) % 5 + x * 5], rr[x + y * 5]);
                }
            }

            // 3.2.4 χ
            for (int y = 0; y < 25; y += 5) {
                for (int x = 0; x < 5; x++) {
                    a[x + y] = ad[x + y] ^ ((~ad[((x + 1) % 5) + y]) & ad[((x + 2) % 5) + y]);
                }
            }

            a[0] ^= RC[ir];
        }
    }

    /**
     * Algorithm 8
     *
     * @param b input / output
     * @return
     */
    private void keccak(byte[] b, int offset) {
        int wb = w / 8;
        for (int c = 0; c < R; c++) {
            int of = offset + wb * c;
            for (int j = 0; j < wb; j++) {
                a[c] ^= (((long) b[of + j] & 0xff)) << (j * 8);
            }
        }
        keccak_f(a);
    }

    @Override
    public void blockWrite(byte[] input, int offset, int len) {
        keccak(input, offset);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        pac.write(input, offset, len);
        length += len;
    }

    /**
     * SHA-512と逆
     *
     * @param src
     * @param len
     * @return
     */
    static byte[] toB(long[] src, int len) {
        byte[] ret = new byte[len];
        for (int i = 0; i < len; i++) {
            ret[i] = (byte) (src[i / 8] >>> ((i % 8) * 8));
        }
        return ret;
    }

    @Override
    protected byte[] engineDigest() {

        // 5.1.
        // Algorithm 9:
        // padding バイト長で計算
        int rblen = R * 8;
        int padlen = rblen - (int) ((length + 1) % rblen) + 1;
        byte[] pad = new byte[padlen];
        pad[0] |= padstart; // 種類判定用おまけbitが付く
        pad[padlen - 1] |= 0x80;

        pac.write(pad, 0, pad.length);

        byte[] digest = toB(a, (d + 7) / 8);
        engineReset();
        return digest;
    }
}
