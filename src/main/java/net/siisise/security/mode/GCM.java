package net.siisise.security.mode;

import java.math.BigInteger;
import net.siisise.security.block.Block;

/**
 * Galois/Counter Mode.
 * CTR + Galois mode
 * 認証用?
 * NIST SP 800-38D
 * https://ja.wikipedia.org/wiki/Galois/Counter_Mode
 * RFC 4106
 */
public class GCM extends StreamMode {

    private byte[] vector;

    public GCM(Block block) {
        super(block);
    }
    
    
    static BigInteger GFBASE = BigInteger.valueOf(0x87l).add(BigInteger.ONE.shiftLeft(128));

    /**
     * gf 2^128
     * gf x^128 + x^7 + x^2 + x + 1
     * @param src
     * @return 
     */
    public static BigInteger gf128(BigInteger src) {
        BigInteger a;
        
        a = src.shiftLeft(1);
        if ( a.testBit(128)) {
            a = a.xor(a.multiply(GFBASE));
        }
        
        return a;
    }
    
    public static long[] gf128(long[] src) {
        byte[] sb = new byte[src.length * 8 + 1];
        ltob(src,sb,1);
        BigInteger sbi = new BigInteger(sb);
        BigInteger r = gf128(sbi);
        byte[] d = r.toByteArray();
        byte[] x = new byte[src.length];
        if ( d.length <= src.length) {
            System.arraycopy(d, 0, x, x.length - d.length, d.length);
        } else {
            System.arraycopy(d, d.length - x.length, x, 0, x.length);
        }
        
        return btol(x);
    }
    
    long[] x(int i) {
        if ( i == 0) return new long[] {0,0};
//        xor(x(i-1),a);
        throw new UnsupportedOperationException();
    }
    
    long[] ghash(long[] h, long[] a, long[] c) {
        
        throw new UnsupportedOperationException();
        
    }
    
    static long[] xor(long[] a, long[] b) {
        long[] c = new long[a.length];
        for ( int i = 0; i < a.length; i++) {
            c[i] = a[i] ^ b[i];
        }
        return c;
    }

    /**
     * 
     * @param key 1つめkey 2つめiv 毎回固有であること
     */
    @Override
    public void init(byte[]... key) {
        byte[][] nkey = new byte[key.length - 1][];
        System.arraycopy(key,0,nkey,0,key.length - 1);
        super.init(nkey);
        byte[] iv = key[key.length - 1];
        vector = new byte[block.getBlockLength() / 8];
        System.arraycopy(iv, 0, vector, 0, vector.length > iv.length ? iv.length : vector.length);
        int vlen = block.getBlockLength() / 8;
        vector = new byte[vlen];        
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
