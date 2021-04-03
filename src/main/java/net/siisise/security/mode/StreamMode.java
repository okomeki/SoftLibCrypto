package net.siisise.security.mode;

import net.siisise.security.block.Block;
import net.siisise.security.stream.Stream;

/**
 * ブロック暗号をストリーム暗号として利用できるモードに.
 *
 */
public abstract class StreamMode extends BlockMode implements Stream {

    protected byte[] vector;
    protected int offset;

    StreamMode(Block block) {
        super(block);
    }

//    @Override
//    public int getBlockLength() {
//        return vector.length * 8;
//    }
    /**
     * ストリーム用暗号化.
     *
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public abstract byte[] encrypt(byte[] src, int offset, int length);

    /**
     * ストリーム用復号
     *
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public abstract byte[] decrypt(byte[] src, int offset, int length);

    static final void xor(byte[] a, byte[] b, int offset, int length) {
        for (int i = 0; i < length; i++) {
            a[i] ^= b[offset + i];
        }
    }

    /**
     * ブロック暗号として利用.
     *
     * @param src
     * @param offset
     * @return
     */
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        return encrypt(src, offset, getBlockLength() * 8);
    }

    /**
     * ブロック暗号として利用.
     *
     * @param src
     * @param offset
     * @return
     */
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return decrypt(src, offset, getBlockLength() * 8);
    }

}
