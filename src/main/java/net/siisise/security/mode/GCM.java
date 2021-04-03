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

    public GCM(Block block) {
        super(block);
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
