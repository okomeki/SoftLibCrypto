package net.siisise.security.block;

/**
 *
 */
public abstract class OneBlock implements Block {

    /**
     * 
     * @param src
     * @param offset
     * @param length 固定サイズの倍数であること.
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int blen = getBlockLength() / 8;
        int len = length / blen;
        byte[] dec = new byte[length];
        byte[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = encrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }

    /**
     * 
     * @param src
     * @param offset
     * @param length 固定サイズの倍数であること.
     * @return 
     */
    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        int blen = getBlockLength() / 32;
        int len = length / blen;
        int[] dec = new int[length];
        int[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = encrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }

    static int[] btoi(final byte[] src) {
        int[] dst = new int[src.length / 4];
        for (int i = 0; i < src.length; i += 4) {
            dst[i / 4]
                    = ( src[i    ]         << 24)
                    | ((src[i + 1] & 0xff) << 16)
                    | ((src[i + 2] & 0xff) <<  8)
                    |  (src[i + 3] & 0xff);
        }
        return dst;
    }

    private static byte[] itob(final int[] src, int offset, int len) {
        byte[] ss = new byte[len * 4];
        for (int i = 0; i < 4; i++) {
            int l = i*4;
            ss[l++] = (byte) (src[i] >> 24);
            ss[l++] = (byte) (src[i] >> 16);
            ss[l++] = (byte) (src[i] >>  8);
            ss[l  ] = (byte)  src[i]       ;
        }
        return ss;
    }
    
    @Override
    public int[] encrypt(int[] src, int offset) {
        int bl = getBlockLength() / 32;
        byte[] b;
        b = itob(src, offset, bl);
        return btoi(encrypt(b,0));
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        int bl = getBlockLength() / 32;
        byte[] b = itob(src, offset, bl);
        return btoi(decrypt(b,0));
    }

    /**
     *
     * @param src
     * @param offset
     * @param dec
     * @param doffset
     * @param length
     */
    @Override
    public void encrypt(byte[] src, int offset, byte[] dec, int doffset, int length) {
        int blen = getBlockLength() / 8;
        int len = length / blen;
        byte[] bdec;
        for ( int i = 0; i < len; i++ ) {
            bdec = encrypt(src, offset);
            System.arraycopy(bdec, 0, dec, doffset, blen);
            offset += blen;
            doffset += blen;
        }
    }

    /**
     * 復号処理.
     * 
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int blen = getBlockLength() / 8;
        int len = length / blen;
        byte[] dec = new byte[length];
        byte[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }
    
    /**
     * 復号処理.
     * 
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int blen = getBlockLength() / 32;
        int len = length / blen;
        int[] dec = new int[length];
        int[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }

    /**
     * 復号処理.
     *
     * @param src
     * @param offset
     * @param dst
     * @param doffset
     * @param length
     */
    @Override
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        int blen = getBlockLength() / 8;
        int len = length / blen;
        byte[] bdec;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dst, doffset, blen);
            offset += blen;
            doffset += blen;
        }
    }
}
