package net.siisise.security.block;

/**
 * ブロック暗号に対応する.
 * byte[]は遅いのでint[]で高速化する
 * encrypt(src, offset) の実装が必要
 */
public abstract class IntBlock extends BaseBlock {

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 32;
        return itob(encrypt(btoi(src, offset, bl), 0));
    }
    
    @Override
    public long[] encrypt(long[] src, int offset) {
        int bl = getBlockLength() / 32;
        return itol(encrypt(ltoi(src, offset, bl), 0));
    }
    
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        int bl = getBlockLength() / 32;
        return itob(decrypt(btoi(src, offset, bl), 0));
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        int bl = getBlockLength() / 32;
        return itol(decrypt(ltoi(src, offset, bl), 0));
    }

    /**
     * 暗号化.
     * ストリームモードでも使用する
     * @param src 元ブロック列
     * @param offset 符号化位置
     * @param length ブロック長
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int[] srcInt = new int[length / 4];
        
        btoi(src,offset,srcInt,length/4);
        int[] ret = encrypt(srcInt, 0, length/4);
        return itob(ret);
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
    public long[] encrypt(long[] src, int offset, int length) {
        int[] srcInt = new int[length *2];
        
        ltoi(src,offset,srcInt,length*2);
        int[] ret = encrypt(srcInt, 0, length*2);
        return itol(ret);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int[] srcInt = new int[length / 4];
        
        btoi(src,offset,srcInt, srcInt.length);
        int[] ret = decrypt(srcInt, 0, srcInt.length);
        return itob(ret);
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
    public long[] decrypt(long[] src, int offset, int length) {
        int[] srcInt = new int[length *2];
        
        ltoi(src,offset,srcInt, srcInt.length);
        int[] ret = decrypt(srcInt, 0, srcInt.length);
        return itol(ret);
    }

    /**
     * 暗号化.
     * @param src 元ブロック列
     * @param offset 符号化位置
     * @param dst 暗号化先
     * @param doffset 先符号化位置
     * @param length 
     */
    @Override
    public void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        int[] srcInt = new int[length / 4];
        
        btoi(src,offset,srcInt,length/4);
        int[] ret = encrypt(srcInt, 0, length/4);
        itob(ret, dst, doffset);
    }

    @Override
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        int[] srcInt = new int[length / 4];
        
        btoi(src,offset,srcInt,length/4);
        int[] ret = decrypt(srcInt, 0, length/4);
        itob(ret, dst, doffset);
    }
}
