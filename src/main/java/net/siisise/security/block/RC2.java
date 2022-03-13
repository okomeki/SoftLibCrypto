package net.siisise.security.block;

/**
 * RFC 2268 A Description of the RC2(r) Encryption Algorithm
 * 16bit CPU
 * 鍵長 128バイト(1024bit)まで?
 */
public class RC2 extends OneBlock {
    
    // 鍵拡張
    // 鍵のバイト列表記
    byte[] L = new byte[128];
    
    public RC2() {
        
    }

    private int getK(int i) {
        int s;
        s = ((L[i*2+1] & 0xff) << 8);
        s |= L[i*2] & 0xff;
        return s;
    }
    
    static byte[] PITABLE = {
    (byte)0xd9, (byte)0x78, (byte)0xf9, (byte)0xc4, (byte)0x19, (byte)0xdd, (byte)0xb5, (byte)0xed,
    (byte)0x28, (byte)0xe9, (byte)0xfd, (byte)0x79, (byte)0x4a, (byte)0xa0, (byte)0xd8, (byte)0x9d,
    (byte)0xc6, (byte)0x7e, (byte)0x37, (byte)0x83, (byte)0x2b, (byte)0x76, (byte)0x53, (byte)0x8e,
    (byte)0x62, (byte)0x4c, (byte)0x64, (byte)0x88, (byte)0x44, (byte)0x8b, (byte)0xfb, (byte)0xa2,
    (byte)0x17, (byte)0x9a, (byte)0x59, (byte)0xf5, (byte)0x87, (byte)0xb3, (byte)0x4f, (byte)0x13,
    (byte)0x61, (byte)0x45, (byte)0x6d, (byte)0x8d, (byte)0x09, (byte)0x81, (byte)0x7d, (byte)0x32,
    (byte)0xbd, (byte)0x8f, (byte)0x40, (byte)0xeb, (byte)0x86, (byte)0xb7, (byte)0x7b, (byte)0x0b,
    (byte)0xf0, (byte)0x95, (byte)0x21, (byte)0x22, (byte)0x5c, (byte)0x6b, (byte)0x4e, (byte)0x82,
    (byte)0x54, (byte)0xd6, (byte)0x65, (byte)0x93, (byte)0xce, (byte)0x60, (byte)0xb2, (byte)0x1c,
    (byte)0x73, (byte)0x56, (byte)0xc0, (byte)0x14, (byte)0xa7, (byte)0x8c, (byte)0xf1, (byte)0xdc,
    (byte)0x12, (byte)0x75, (byte)0xca, (byte)0x1f, (byte)0x3b, (byte)0xbe, (byte)0xe4, (byte)0xd1,
    (byte)0x42, (byte)0x3d, (byte)0xd4, (byte)0x30, (byte)0xa3, (byte)0x3c, (byte)0xb6, (byte)0x26,
    (byte)0x6f, (byte)0xbf, (byte)0x0e, (byte)0xda, (byte)0x46, (byte)0x69, (byte)0x07, (byte)0x57,
    (byte)0x27, (byte)0xf2, (byte)0x1d, (byte)0x9b, (byte)0xbc, (byte)0x94, (byte)0x43, (byte)0x03,
    (byte)0xf8, (byte)0x11, (byte)0xc7, (byte)0xf6, (byte)0x90, (byte)0xef, (byte)0x3e, (byte)0xe7,
    (byte)0x06, (byte)0xc3, (byte)0xd5, (byte)0x2f, (byte)0xc8, (byte)0x66, (byte)0x1e, (byte)0xd7,
    (byte)0x08, (byte)0xe8, (byte)0xea, (byte)0xde, (byte)0x80, (byte)0x52, (byte)0xee, (byte)0xf7,
    (byte)0x84, (byte)0xaa, (byte)0x72, (byte)0xac, (byte)0x35, (byte)0x4d, (byte)0x6a, (byte)0x2a,
    (byte)0x96, (byte)0x1a, (byte)0xd2, (byte)0x71, (byte)0x5a, (byte)0x15, (byte)0x49, (byte)0x74,
    (byte)0x4b, (byte)0x9f, (byte)0xd0, (byte)0x5e, (byte)0x04, (byte)0x18, (byte)0xa4, (byte)0xec,
    (byte)0xc2, (byte)0xe0, (byte)0x41, (byte)0x6e, (byte)0x0f, (byte)0x51, (byte)0xcb, (byte)0xcc,
    (byte)0x24, (byte)0x91, (byte)0xaf, (byte)0x50, (byte)0xa1, (byte)0xf4, (byte)0x70, (byte)0x39,
    (byte)0x99, (byte)0x7c, (byte)0x3a, (byte)0x85, (byte)0x23, (byte)0xb8, (byte)0xb4, (byte)0x7a,
    (byte)0xfc, (byte)0x02, (byte)0x36, (byte)0x5b, (byte)0x25, (byte)0x55, (byte)0x97, (byte)0x31,
    (byte)0x2d, (byte)0x5d, (byte)0xfa, (byte)0x98, (byte)0xe3, (byte)0x8a, (byte)0x92, (byte)0xae,
    (byte)0x05, (byte)0xdf, (byte)0x29, (byte)0x10, (byte)0x67, (byte)0x6c, (byte)0xba, (byte)0xc9,
    (byte)0xd3, (byte)0x00, (byte)0xe6, (byte)0xcf, (byte)0xe1, (byte)0x9e, (byte)0xa8, (byte)0x2c,
    (byte)0x63, (byte)0x16, (byte)0x01, (byte)0x3f, (byte)0x58, (byte)0xe2, (byte)0x89, (byte)0xa9,
    (byte)0x0d, (byte)0x38, (byte)0x34, (byte)0x1b, (byte)0xab, (byte)0x33, (byte)0xff, (byte)0xb0,
    (byte)0xbb, (byte)0x48, (byte)0x0c, (byte)0x5f, (byte)0xb9, (byte)0xb1, (byte)0xcd, (byte)0x2e,
    (byte)0xc5, (byte)0xf3, (byte)0xdb, (byte)0x47, (byte)0xe5, (byte)0xa5, (byte)0x9c, (byte)0x77,
    (byte)0x0a, (byte)0xa6, (byte)0x20, (byte)0x68, (byte)0xfe, (byte)0x7f, (byte)0xc1, (byte)0xad
    };
    
    /**
     * Tバイト 1 &lt;= T &lt;= 128
     * T1 = 有効鍵長 (128ぐらい)
     * T = 
     * T8 = key.length 
     * @param key
     */
    @Override
    public void init(byte[] key) {
        // ToDo: 長さエラーチェック
        int t = key.length;
        System.arraycopy(key,0,L,0,t);
        int t1 = t*8;
        int t8 = (t1+7)/8; // 実質t
        // 最後ビットのマスク?
        int tm = 0xff % (1 << (8 + t1 - 8*t8)); // 0xff;
     
        // 鍵拡張
        for (int i = t; i <= 127; i++ ) {
            L[i] = (byte)(PITABLE[(L[i-1] + L[i-t]) & 0xff]);
        }
        L[128-t8] = PITABLE[L[128-t8] & tm];
        
        for ( int i = 127-t8; i >= 0; i-- ) {
            L[i] = PITABLE[(L[i+1] ^ L[i+t8]) & 0xff];
        }
    }

    @Override
    public void init(byte[]... keys) {
        throw new SecurityException("さぽーとしてない");
    }

    @Override
    public int getBlockLength() {
        return 64;
    }
    
    static final int[] s = {1,2,3,5};
    
    private void mix(short[] r, int j) {
        // 3.2 みきしんぐ
        for (int i = 0; i < 4; i++) {
            // 3.1 みっくす
            int i1 = (i + 3) & 0x3;
            int rff = (r[i] + getK(j+i) + (r[i1] & r[i^2]) + ((~r[i1]) & r[i1^2])) & 0xffff;
            r[i] = (short) ((rff << s[i]) | (rff >>> (16 - s[i])));
        }
    }
    
    private void mash(short[] r) {
        for (int i = 0; i < 4; i++) {
            int i1 = (i+3) & 0x3;
            r[i] = (short) (r[i] + getK(r[i1] & 63));
        }
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        //int ss = ;
        short[] R = new short[4];
        for ( int i = 0; i < 4; i++ ) {
            R[i] = (short) ((src[offset + i*2] & 0xff) | (src[offset + i*2+1] << 8));
        }
        for ( int i = 0; i < 5; i++) {
            mix(R,i*4);
        }
        mash(R);
        for ( int i = 0; i < 6; i++) {
            mix(R,i*4+20);
        }
        mash(R);
        for ( int i = 0; i < 5; i++) {
            mix(R,i*4+44);
        }

        byte[] ret = new byte[8];
        for ( int i = 0; i < 4; i++ ) {
            ret[i*2] = (byte) R[i];
            ret[i*2+1]= (byte) (R[i] >>> 8);
        }
        return ret;
    }
    
    private void rmix(short[] r, int j) {
        for (int i = 3; i >= 0; i--) {
            int i1 = (i-1) & 3;
            int rff = r[i] & 0xffff;
            rff = (rff >>> s[i]) | (rff << (16 - s[i]));
            r[i] = (short) (rff - getK(j+i) - (r[i1] & r[i^2]) - ((~r[i1]) & r[i1^2]));
        }
    }
    
    private void rmash(short[] r) {
        for (int i = 3; i >= 0; i--) {
            int i1 = (i-1) & 0x3;
            r[i] = (short) (r[i] - getK(r[i1] & 63));
        }
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        short[] R = new short[4];
        for ( int i = 0; i < 4; i++ ) {
            R[i] = (short) ((src[offset + i*2] & 0xff) | (src[offset + i*2+1] << 8));
        }
        for ( int i = 0; i < 5; i++) {
            rmix(R,60-i*4);
        }
        rmash(R);
        for ( int i = 0; i < 6; i++) {
            rmix(R,40-i*4);
        }
        rmash(R);
        for ( int i = 0; i < 5; i++) {
            rmix(R,16-i*4);
        }

        byte[] r = new byte[8];
        for ( int i = 0; i < 4; i++ ) {
            r[i*2] = (byte) R[i];
            r[i*2+1]= (byte) (R[i] >>> 8);
        }
        return r;
    }
    
}
