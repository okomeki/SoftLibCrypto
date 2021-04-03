package net.siisise.security.mode;

import net.siisise.security.block.Block;

/**
 * Cipher Block Chaining.
 * iv は 0 でいいがJavaのは必須?
 */
public class CBC extends BlockMode {

    private byte[] vector;

    public CBC(Block block) {
        super(block);
        vector = new byte[block.getBlockLength() / 8];
    }

    @Override
    public void init(byte[] key) {
        super.init(key);
        vector = new byte[block.getBlockLength() / 8];
    }

    @Override
    public void init(byte[] key, byte[] iv) {
        super.init(key);
        vector = new byte[block.getBlockLength() / 8];
        System.arraycopy(iv, 0, vector, 0, iv.length);
    }

    @Override
    public void init(Block block, byte[] key) {
        super.init(block, key);
        vector = new byte[block.getBlockLength() / 8];
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        for (int i = 0; i < vector.length; i++) {
            vector[i] ^= src[offset + i];
        }
        byte[] ret = block.encrypt(vector, 0);
        // 複製が必要かもしれない
        System.arraycopy(ret, 0, vector, 0, ret.length);
        return ret;
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        byte[] ret = new byte[length];
        int roffset = 0;
        int bl = getBlockLength() / 8;

        while (length > 0) {
            for (int i = 0; i < vector.length; i++) {
                vector[i] ^= src[offset + i];
            }
            vector = block.encrypt(vector, 0);
            // 複製が必要かもしれない
            System.arraycopy(vector, 0, ret, roffset, vector.length);
            length -= bl;
            offset += bl;
            roffset += bl;
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        byte[] n = new byte[vector.length];
        System.arraycopy(src, offset, n, 0, vector.length);
        byte[] ret = block.decrypt(n, 0);
        // 複製が必要かもしれない
        for (int i = 0; i < vector.length; i++) {
            ret[i] ^= vector[i];
        }
        vector = n;
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        byte[] ret = new byte[length];
        int roffset = 0;
        int bl = vector.length;
        byte[] re;

        re = block.decrypt(src, offset);
        for (int i = 0; i < bl; i++) {
            ret[i] = (byte) (re[i] ^ vector[i]);
        }

        offset += bl;
        roffset += bl;
        length -= bl;

        int voffset = offset - bl;

        while (length > 0) {
            re = block.decrypt(src, offset);
            for (int i = 0; i < bl; i++) {
                ret[roffset++] = (byte) (re[i] ^ src[voffset++]);
            }
            length -= bl;
            offset += bl;
        }
        System.arraycopy(src, voffset, vector, 0, bl);
        return ret;
    }
}
