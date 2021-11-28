package net.siisise.security.mode;

import net.siisise.security.block.Block;

/**
 * Electoric Codebook (ECB)
 * 特に指定しない
 */
public class ECB extends BlockMode {

    public ECB(Block block) {
        super(block);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        return block.encrypt(src, offset);
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        return block.encrypt(src, offset);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return block.decrypt(src, offset);
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        return block.decrypt(src, offset);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        return block.encrypt(src, offset, length);
    }

    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        return block.encrypt(src, offset, length);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return block.decrypt(src, offset, length);
    }

    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        return block.decrypt(src, offset, length);
    }
}
