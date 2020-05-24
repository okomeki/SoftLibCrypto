package net.siisise.security.digest;

import net.siisise.security.io.BlockOutputStream;

/**
 * RFC 1320
 * @deprecated RFC 6150
 */
public class MD4 extends BlockMessageDigest {

    private int[] ad;

    public MD4() {
        super("MD4");
        engineReset();
    }

    @Override
    protected int engineGetDigestLength() {
        return 16;
    }
    
    @Override
    public int getBitBlockLength() {
        return 512;
    }

    @Override
    protected void engineReset() {
        ad = new int[]{0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476};
        length = 0;
        pac = new BlockOutputStream(this);
    }

    static final int[] S1 = {3, 19, 11, 7};
    static final int[] S2 = {3, 13, 9, 5};
    static final int[] S3 = {3, 15, 11, 9};
    
    private void abcdf(int m, int i) {
        int e = -i & 3;
        int b = ad[(1 - i) & 3];
        int c = ad[(2 - i) & 3];
        int d = ad[(3 - i) & 3];
        m += ad[e] + ((b & c) | ~b & d);
        d = S1[e];
        ad[e] = ((m << d) | (m >>> (32 - d)));
    }

    private void abcdg(int m, int i) {
        int e = -i & 3;
        int b = ad[(1 - i) & 3];
        int c = ad[(2 - i) & 3];
        int d = ad[(3 - i) & 3];
        m += ad[e] + ((b & c) | (b & d) | (c & d)) + 0x5a827999;
        d = S2[e];
        ad[e] = ((m << d) | (m >>> (32 - d)));
    }

    private void abcdh(int m, int i) {
        int e = -i & 3;
        int b = ad[(1 - i) & 3];
        int c = ad[(2 - i) & 3];
        int d = ad[(3 - i) & 3];
        m += ad[e] + (b ^ c ^ d) + 0x6ed9eba1;
        d = S3[e];
        ad[e] = ((m << d) | (m >>> (32 - d)));
    }

    int x[] = new int[16];

    @Override
    public void blockWrite(byte[] input, int offset, int len) {

        int aa, bb, cc, dd;
        for (int j = 0; j < 16; j++) {
            int of = offset + j*4;
            x[j] = (input[of] & 0xff) + ((input[of+1] & 0xff) << 8)
                    + ((input[of+2] & 0xff) << 16) + ((input[of+3] & 0xff) << 24);
        }
        aa = ad[0];
        bb = ad[1];
        cc = ad[2];
        dd = ad[3];

        /* Round 1. */
        for (int i = 0; i < 16; i++) {
            abcdf(x[i], i);
        }
        /* Round 2. */
        for (int i = 0; i < 16; i++) {
            abcdg(x[(i * 4 + i / 4) & 0x0f], i);
        }
        /* Round 3. */
        for (int i = 0; i < 16; i++) {
            abcdh(x[((i & 1) << 3) | ((i&2) << 1) | ((i&4) >> 1) | ((i&8) >> 3)], i);
        }

        ad[0] += aa;
        ad[1] += bb;
        ad[2] += cc;
        ad[3] += dd;
    }

    @Override
    protected byte[] engineDigest() {

        long len = length;

        // ラスト周
        // padding
        pac.write(new byte[]{(byte) 0x80});
        int padlen = 512 - (int) ((len + 64 + 8) % 512);
        pac.write(new byte[padlen / 8]);
        byte[] lena = new byte[8];
        for (int i = 0; i < 8; i++) {
            lena[i] = (byte) len;
            len >>>= 8;
        }

        pac.write(lena, 0, lena.length);

        byte[] ret = new byte[16];
        for (int i = 0; i < 16; i++) {
            ret[i] = (byte) (ad[i / 4] >>> ((i & 3) * 8));
        }
        engineReset();
        return ret;
    }
}
