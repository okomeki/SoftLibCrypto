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
