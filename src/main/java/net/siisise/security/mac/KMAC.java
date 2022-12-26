package net.siisise.security.mac;

/**
 * SHA-3系に用意されているらしい標準MAC
 */
public class KMAC implements MAC {

    @Override
    public void init(byte[] key) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] doFinal() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getMacLength() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
