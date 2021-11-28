package net.siisise.security.mode;

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

    /**
     * 
     * @param key
     * @param iv 毎回固有であること
     */
    @Override
    public void init(byte[]... key) {
        super.init(key[0]);
        byte[] iv = key[1];
        vector = new byte[block.getBlockLength() / 8];
        System.arraycopy(iv, 0, vector, 0, vector.length > iv.length ? iv.length : vector.length);
        int vlen = block.getBlockLength() / 8;
        vector = new byte[vlen];        
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }
    
}
