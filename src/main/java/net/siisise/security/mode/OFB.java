package net.siisise.security.mode;

import net.siisise.security.block.Block;

/**
 * Output Feedback.
 * ストリームにも転用可能. (OFB8とかいうらしい)
 */
public final class OFB extends StreamMode {

    public OFB(Block block, byte[] key, byte[] iv) {
        super(block);
        init(key, iv);
    }

    @Override
    public void init(byte[] key, byte[] iv) {
        super.init(key);
        vector = new byte[getBlockLength() / 8];
        System.arraycopy(iv, 0, vector, 0, vector.length > iv.length ? iv.length : vector.length);
        next();
    }
    
    void next() {
        vector = block.encrypt(vector, 0);
    }
    
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int l = vector.length - this.offset;
        byte[] ret = new byte[length];
        int ro = 0;
        while ( length > 0 ) {
            if ( l > length ) {
                l = length;
            }
            for ( int i = 0; i < l; i++ ) {
                ret[ro++] = (byte) (vector[this.offset++] ^ src[offset++]);
                length--;
            }
            if ( this.offset >= vector.length ) {
                this.offset = 0;
                l = vector.length;
                next();
            }
        }
        return ret;
    }
    
    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }
    

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        byte[] nv = block.encrypt(vector, 0);
        byte[] ret = vector; // 配列の使い回し
        
        for (int i = 0; i < vector.length; i++) {
            ret[i] ^= src[offset + i];
        }

        vector = nv;
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return encrypt(src, offset);
    }

}
