package net.siisise.security.mode;

import java.math.BigInteger;
import java.util.Arrays;
import net.siisise.security.block.Block;

/**
 * Counter
 */
public class CTR extends StreamMode {

    BigInteger ivector;
    int vlen;

    public CTR(Block b, byte[] key, byte[] iv) {
        super(b);
        init(key, iv);
    }

    @Override
    public void init(byte[]... key) {
        super.init(key[0]);
        byte[] iv = key[1];
        vlen = block.getBlockLength() / 8;
        vector = new byte[vlen];
        ivector = new BigInteger(iv);

        next();
    }

    void next() {
        byte[] v = ivector.toByteArray();
        int l = vlen - v.length; // ToDo: オーバーフロー未対応
        Arrays.fill(vector, 0, l, (byte) 0);
        System.arraycopy(v, 0, vector, l, v.length);
        ivector = ivector.add(BigInteger.ONE);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {

        byte[] ret = block.encrypt(vector, 0);
        for (int i = 0; i < vlen; i++) {
            ret[i] ^= src[offset + i];
        }
        next();
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return encrypt(src, offset);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }

}
