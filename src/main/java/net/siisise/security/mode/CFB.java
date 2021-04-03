package net.siisise.security.mode;

import net.siisise.security.block.Block;

/**
 * Cipher Feedback.
 * ストリームにも転用可能 (CFB8とかいうらしい)
 * 復号処理の並列化が可能
 */
public final class CFB extends StreamMode {

    public CFB(Block block, byte[] key, byte[] iv) {
        super(block);
        init(key, iv);
    }

    @Override
    public void init(byte[] key, byte[] iv) {
        super.init(key);
        vector = new byte[block.getBlockLength() / 8];
        System.arraycopy(iv, 0, vector, 0, vector.length > iv.length ? iv.length : vector.length);
        vector = block.encrypt(vector, 0);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        xor(vector, src, offset, vector.length);
        byte[] ret = vector;
        vector = block.encrypt(ret, 0);
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        byte[] ret = vector;
        xor(ret, src, offset, ret.length);
        vector = block.encrypt(src, offset);
        return ret;
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int l = vector.length - this.offset;
        byte[] ret = new byte[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                vector[this.offset] ^= src[offset++];
                ret[ro++] = vector[this.offset++];
                length--;
            }
            if (this.offset >= vector.length) {
                this.offset = 0;
                vector = block.encrypt(vector, 0);
                l = vector.length;
            }
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int l = vector.length - this.offset;
        byte[] ret = new byte[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                ret[ro++] = (byte) (vector[this.offset + i] ^ src[offset + i]);
                vector[this.offset++] = src[offset++];
                length--;
            }
            if (this.offset >= vector.length) {
                this.offset = 0;
                vector = block.encrypt(vector, 0);
                l = vector.length;
            }
        }
        return ret;
    }

}
