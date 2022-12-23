package net.siisise.security.mac;

import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;

/**
 * Cipher-based Message Authentication Code (CMAC).
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

    private byte[] k1; // 最後のブロックがブロック長と等しい場合
    private byte[] k2; // 最後のブロックがブロック長より短い場合
    private long len;
    private Packet m;
    // Step 5.
    private byte[] x;
    private byte[] constRb;

    /**
     * AES-CMAC
     */
    public CMAC() {
        this(new AES());
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

    /** GFへ */
    private byte[] gf(byte[] s) {
        byte[] v = shl(s);
        if ((s[0] & 0x80) != 0) {
            v = Bin.xor(v, constRb);
        }
        return v;
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
        byte[] constZero = new byte[key.length];
        constRb = new byte[key.length];
        constRb[constRb.length - 1] = (byte)0x87;
        byte[] L = block.encrypt(constZero);
        // ガロア?
        k1 = gf(L);
        k2 = gf(k1);
        m = new PacketA();
        len = 0;
        // Step 5.
        x = new byte[key.length];
    }
    
    private void step6a() {
        // Step 6. A
        byte[] mi = new byte[x.length];
        long mlen = m.length();
        while ( mlen > x.length ) {
            mlen -= x.length;
            m.read(mi);
            x = block.encrypt(Bin.xor(x, mi));
        }
    }

    @Override
    public void update(byte[] src) {
        m.write(src);
        len += src.length;
        step6a();
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        m.write(src, offset, length);
        len += length;
        step6a();
    }

    @Override
    public byte[] doFinal(byte[] src) {
        m.write(src);
        len += src.length;
        step6a();
        return doFinal();
    }

    @Override
    public byte[] doFinal() {
        // Step 2.
        long n = (int)((len + k1.length - 1) / k1.length);
        // Step 3.
        boolean pad;
        if ( n == 0 ) {
            pad = true;
        } else {
            pad = ( len % k1.length != 0 );
        }
        byte[] M_last;
        // Step 4.
        if ( !pad ) {
            M_last = Bin.xor(m.toByteArray(), k1);
        } else { // padding(M)
            m.write(0x80);
            m.write(new byte[16 - m.size()]);
            M_last = Bin.xor(m.toByteArray(), k2);
        }
        // 次の初期化
        byte[] x2 = x;
        x = new byte[x.length];
        len = 0;
        // Step 6. B Step 7.
        return block.encrypt(Bin.xor(M_last, x2));
    }

    @Override
    public int getMacLength() {
        return (block.getBlockLength() + 7) / 8;
    }

    
}
