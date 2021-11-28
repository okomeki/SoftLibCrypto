package net.siisise.security.block;

/**
 *
 */
public abstract class IntBlock implements Block {

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 32;
        int[] block = new int[bl];
        btoi(src, offset, block, bl);
        return itob(encrypt(block, 0));
    }
    
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 32;
        int[] block = new int[bl];
        btoi(src, offset, block, bl);
        int[] plane = decrypt(block, 0);
        return itob(plane);
    }
    
    /**
     * 
     * @param src バイト列
     * @param offset 位置
     * @param dst 戻りint列
     * @param length int長
     */
    public static void btoi(final byte[] src, int offset, int[] dst, int length) {
        int t = offset;
        for (int i = 0; i < length; i++) {
            dst[i]
                    = ( src[t]         << 24)
                    | ((src[t+1] & 0xff) << 16)
                    | ((src[t+2] & 0xff) <<  8)
                    |  (src[t+3] & 0xff);
            t+=4;
        }
    }

    public static int[] btoi(final byte[] src) {
        int t = 0;
        int dl = src.length / 4;
        int[] dst = new int[dl];
        for (int i = 0; i < dl; i++) {
            dst[i]
                    = ( src[t]         << 24)
                    | ((src[t+1] & 0xff) << 16)
                    | ((src[t+2] & 0xff) <<  8)
                    |  (src[t+3] & 0xff);
            t+=4;
        }
        return dst;
    }

    public static byte[] itob(final int[] src) {
        byte[] ss = new byte[src.length*4];
        for (int i = 0; i < src.length; i++) {
            int l = i*4;
            ss[l++] = (byte) (src[i] >> 24);
            ss[l++] = (byte) (src[i] >> 16);
            ss[l++] = (byte) (src[i] >>  8);
            ss[l  ] = (byte)  src[i]       ;
        }
        return ss;
    }

    public static byte[] itob(final int[] src, byte[] ss, int doffset) {
        for (int i = 0; i < src.length; i++) {
            int l = doffset + i*4;
            ss[l++] = (byte) (src[i] >> 24);
            ss[l++] = (byte) (src[i] >> 16);
            ss[l++] = (byte) (src[i] >>  8);
            ss[l  ] = (byte)  src[i]       ;
        }
        return ss;
    }
    
    public byte[] encrypt(byte[] src) {
        return encrypt(src, 0, src.length);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int[] srcInt = new int[length / 4];
        
        btoi(src,offset,srcInt,length/4);
        int[] ret = encrypt(srcInt, 0, length/4);
        return itob(ret);
    }

    @Override
    public void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        int[] srcInt = new int[length / 4];
        
        btoi(src,offset,srcInt,length/4);
        int[] ret = encrypt(srcInt, 0, length/4);
        itob(ret, dst, doffset);
    }

    public int[] encrypt(int[] src) {
        return encrypt(src, 0, src.length);
    }

    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        int[] ret = new int[length];
        int of = 0;
        while (length > of) {
            int[] x = encrypt(src,offset);
            System.arraycopy(x, 0, ret, of, x.length);
            offset += x.length;
            of += x.length;
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int[] srcInt = new int[length / 4];
        
        btoi(src,offset,srcInt, srcInt.length);
        int[] ret = decrypt(srcInt, 0, srcInt.length);
        return itob(ret);
    }

    @Override
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int[] ret = new int[length];
        int of = 0;
        while (length > of) {
            int[] x = decrypt(src,offset);
            System.arraycopy(x, 0, ret, of, x.length);
            offset += x.length;
            of += x.length;
        }
        return ret;
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
}
