package net.siisise.security.mode;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collector;
import java.util.stream.Collector.Characteristics;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;
import net.siisise.security.mac.GHASH;

/**
 * TLS 1.2のモードなど.
 * CTR の微修正.
 * 
 * Galois/Counter Mode(GCMx) and GMAC NIST SP 800- 38D, November 2007
 * https://nvlpubs.nist.gov/nistpubs/legacy/sp/nistspecialpublication800-38d.pdf
 * Counter は IV(96bit) + 1(32bit) または GHASH らしい
 * P の長さ 2^39 -256 32bit counter の限界か
 * Aの長さ 2^64 -1
 * IVの長さ 2^64 -1
 * 
 *  RFC 5288 RFC 5289
 */
public class GCM extends CTR {
    
    byte[] iv;
    int[] iiv;
    long[] liv;
    int count;
    GHASH gh;
    byte[] tag;
    
    private byte[] H;

    public GCM() {
        super(new AES());
    }
    
    /**
     * AES GCM
     * @param block AES 他
     */
    public GCM(Block block) {
        super(block);
    }

    @Override
    public int getBlockLength() {
        return 128;
    }

    /**
     * 
     * iv 96bit または ?
     * iv は使い捨て( 再利用禁止、衝突するRNDよりCountがいい )
     * @param keyAndParam key, iv, a
     */
    @Override
    public void init(byte[]... keyAndParam) {
        block.init(keyAndParam[0]);
        H = block.encrypt(new byte[128 / 8]);
        iv = Y0(keyAndParam[0], keyAndParam[1]);
        iiv = btoi(iv);
//        iiv[3] = 1;
//        iv = itob(iiv);
        liv = btol(iv);
        count = 1;
        // GHASH
        tag = null;
        gh = new GHASH();
        if ( keyAndParam.length > 2) {
            gh.init(keyAndParam[0], keyAndParam[2]);
        } else {
            gh.init(keyAndParam[0], new byte[0]);
        }
    }

    private byte[] Y0(byte[] key, byte[] iv) {
        if (iv.length == 12) {
            byte[] m = new byte[16];
            System.arraycopy(iv, 0, m, 0, 12);
            m[15] = 1;
            return m;
        }
        GHASH ivgh = new GHASH();
        ivgh.init(key);// aなし
        return ivgh.doFinal(iv);
    }

    /**
     * Section 6.2
     * @param x IV + カウンター
     * @param s カウンタービット数
     * @return 
     */
    private byte[] incs8() {
        byte[] cb = new byte[16];
        System.arraycopy(iv, 0, cb, 0, 12);
        
        cb[12] = (byte) (count >>> 24);
        cb[13] = (byte) (count >>> 16);
        cb[14] = (byte) (count >>> 8);
        cb[15] = (byte) count;
        count++;
        return cb;
    }

    private int[] incs32() {
        int[] cb = new int[4];
        System.arraycopy(iiv, 0, cb, 0, 3);
        
        cb[3] = count++;
        return cb;
    }
    
    private int[] c32(int c) {
        int[] cb = new int[4];
        System.arraycopy(iiv, 0, cb, 0, 3);
        
        cb[3] = c;
        return cb;
    }

    private long[] incs64() {
        long[] cb = new long[2];
        System.arraycopy(liv, 0, cb, 0, 2);
        
        cb[1] &= 0xffffffff00000000l;
        cb[1] |= count & 0xffffffffl;
        count++;
        return cb;
    }
    
    private long[] c64(long c) {
        long[] cb = new long[2];
        System.arraycopy(liv, 0, cb, 0, 2);
        
        cb[1] &= 0xffffffff00000000l;
        cb[1] |= count & 0xffffffffl;
        return cb;
    }

    Collector<byte[], ?, Packet> toPac = Collector.of(
            PacketA::new,
            Packet::write,
            (p1, p2) -> {
                p1.write(p2);
                return p1;
            },
            Characteristics.IDENTITY_FINISH);
    

    private Packet xor8(int len) {
        int nlen = count + (len + 15 ) / 16;
        List<Integer> nl = new ArrayList<>(nlen);
        for (int i = count; i < nlen; i++ ) {
            nl.add(i);
        }
        count += nlen;
        return nl.parallelStream().map(x -> ltob(block.encrypt(c64(x)))).collect(toPac);
    }

    private int[][] xor32(int len) {
        int nlen = count + (len + 15 ) / 16;
        List<Integer> nl = new ArrayList<>(nlen);
        for (int i = count; i < nlen; i++ ) {
            nl.add(i);
        }
        count += nlen;
        return (int[][]) nl.parallelStream().map(x -> block.encrypt(c32(x))).toArray();
    }

    static byte[] len(byte[] x) {
        return Bin.toByte(x.length * 8l);
    }

    private Packet enc = new PacketA();

    /**
     * ブロック用
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public int[] encrypt(int[] src, int offset) {
        int[] ret = block.encrypt(incs32());
        
        for ( int i = 0; i < ret.length; i++ ) {
            ret[i] ^= src[offset + i];
        }
        gh.update(itob(ret));
        
        return ret;
    }

    @Override
    public long[] encrypt(long[] src, int offset) {
        long[] ret = block.encrypt(incs64());
        
        for ( int i = 0; i < ret.length; i++ ) {
            ret[i] ^= src[offset + i];
        }
        gh.update(ltob(ret));
        
        return ret;
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        return encrypt(src, offset);
    }
    
    /**
     * ストリーム用
     * @param src 元データ
     * @param offset 位置
     * @param length サイズ
     * @return 符号化
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int hl = length - enc.size();
        if ( hl > 0 ) {
            enc.write(xor8(hl));
        }
        byte[] encd = new byte[length];
        enc.read(encd);
        for ( int i = 0; i < length; i++ ) {
            encd[i] ^= src[offset + i];
        }
        gh.update(encd);
        return encd;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }

    public byte[] tag() {
        if ( tag == null ) {
            tag = gh.doFinal();
        }
        byte[] r = new byte[tag.length];
        System.arraycopy(tag, 0, r, 0, tag.length);
        return r;
    }
}
