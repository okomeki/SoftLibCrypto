package net.siisise.security.mac;

import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.math.GF;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;

/**
 * Cipher-based Message Authentication Code (CMAC).
 * 
 * GFなどで128bit 固定なのかも.
 * 
 * One-Key CBC MAC1 (OMAC1) と同じ
 * 
 * CBC-MAC の更新
 * XCBC / OMAC / CMAC = OMAC1 / TMAC
 * 
 * Tetsu Iwata, Kaoru Kurosawa、OMAC: One-Key CBC MAC、2003年、Fast Software Encryption, FSE 2003, LNCS 2887, pp. 129-153, Springer.
 * 
 * RFC 4493 The AES-CMAC Algorithm.
 * NIST SP 800-38B Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication.
 */
public class CMAC implements MAC {

    private final Block block; // E

    byte[] k1; // 最後のブロックがブロック長と等しい場合
    byte[] k2; // 最後のブロックがブロック長より短い場合
    private long len;
    private Packet m;
    // Step 5.
    private byte[] x;

    /**
     * AES-CMAC
     */
    public CMAC() {
        this(new AES());
    }

    /**
     * AES-CMAC
     * @param key AES key 128bit
     */
    public CMAC(byte[] key) {
        this(new AES());
        init(key);
    }

    /**
     * 特定のブロック暗号のCMACっぽいものにする?
     * XXX-CMAC
     * @param e ブロック暗号 E 
     */
    public CMAC(Block e) {
        block = e;
        x = new byte[(block.getBlockLength() + 7 ) / 8];
    }

    /** BinかGF へ */
    private byte[] shl(byte[] l) {
        byte[] n = new byte[l.length];
        n[0] = (byte)(l[0] << 1);
        int v = (l[0] & 0xff);
        for (int i = 1; i < l.length; i++) {
            v = (v << 8) | (l[i] & 0xff);
            n[i - 1] = (byte)(v >>> 7);
        }
        n[l.length - 1] = (byte)(v << 1);
        return n;
    }

    /**
     * RFC 4493 Section 2.3. Subkey Generation Algorithm
     * @param key AES鍵 AES-128 128bit
     */
    @Override
    public void init(byte[] key) {
        if ( key.length != (block.getBlockLength() + 7) / 8 ) { // 128bit 鍵とブロック長が同じなのは(仮)
            throw new SecurityException();
        }
        block.init(key);
        byte[] L = block.encrypt(new byte[key.length]);
        GF gf = new GF(128,GF.FF128);
        k1 = gf.x(L);
        k2 = gf.x(k1);
        m = new PacketA();
        len = 0;
        // Step 5.
        x = new byte[key.length];
    }
/*    
    private void step6a() {
        // Step 6. A
        byte[] mi = new byte[x.length];
        long mlen = m.length();
        while ( mlen > x.length ) {
            m.read(mi);
            enc(mi);
            mlen -= x.length;
        }
    }
*/
    /**
     * x = Ek(x^a)
     * @param a データ
     */
    private void enc(byte[] a, int offset) {
        for ( int i = 0; i < x.length; i++ ) {
            x[i] ^= a[offset + i];
        }
        x = block.encrypt(x);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        len += length;
        int ml = m.size();
        int last = offset + length;
        // Strp 6. A
        if ( ml > 0 && ml + length > x.length ) {
            int wlen = x.length - ml;
            m.write(src,offset,wlen);
            offset += wlen;
            enc(m.toByteArray(), 0);
        }
        while ( offset + x.length < last ) {
            enc(src,offset);
            offset += x.length;
        }
        m.write(src, offset, last - offset);
    }

    @Override
    public byte[] doFinal() {
        // Step 3. Step 4.
        byte[] M_last;
        if ( (len == 0) || ( len % k1.length != 0 ) ) { // padding(M)
            m.write(0x80);
            m.write(new byte[k2.length - m.size()]);
            M_last = Bin.xor(m.toByteArray(), k2);
        } else {
            M_last = Bin.xor(m.toByteArray(), k1);
        }
        // Step 6. B Step 7.
        M_last = block.encrypt(Bin.xorl(M_last, x));
        // 次の初期化
        x = new byte[x.length];
        len = 0;
        return M_last;
    }

    @Override
    public int getMacLength() {
        return (block.getBlockLength() + 7) / 8;
    }

    
}
