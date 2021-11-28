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

    /**
     * 
     * @param key 鍵とInitial Vector
     */
    @Override
    public void init(byte[]... key) {
        super.init(key[0]);
        vector = new byte[block.getBlockLength() / 8];
        vectori = new int[block.getBlockLength() / 32];
        int[] d = new int[key[0].length / 4];
        System.arraycopy(key[1], 0, vector, 0, vector.length > key[1].length ? key[1].length : vector.length);
        btoi(vector,0,vectori,vectori.length);
        vectori = block.encrypt(vectori, 0);
    }

    /**
     * Block Mode encrypt
     * @param src
     * @param offset
     * @return 
     */
/*
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        xor(vector, src, offset, vector.length);
        byte[] ret = vector;
        vector = block.encrypt(ret, 0);
        return ret;
    }
*/
    @Override
    public int[] encrypt(int[] src, int offset) {
        xor(vectori, src, offset, vector.length);
        int[] ret = vectori;
        vectori = block.encrypt(ret, 0);
        return ret;
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        int[] ret = vectori;
        xor(ret, src, offset, ret.length);
        vectori = block.encrypt(src, offset);
        return ret;
    }

    /**
     * Stream Mode encrypt
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        int l = vectori.length - this.offset;
        int[] ret = new int[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                vectori[this.offset] ^= src[offset++];
                ret[ro++] = vectori[this.offset++];
                length--;
            }
            if (this.offset >= vectori.length) {
                this.offset = 0;
                vectori = block.encrypt(vectori, 0);
                l = vectori.length;
            }
        }
        return ret;
    }

    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int l = vectori.length - this.offset;
        int[] ret = new int[length];
        int ro = 0;
        while (ro < ret.length) {
            if (length < l) {
                l = length;
            }
            for (int i = 0; i < l; i++) {
                ret[ro++] = (byte) (vectori[this.offset + i] ^ src[offset + i]);
                vectori[this.offset++] = src[offset++];
                length--;
            }
            if (this.offset >= vectori.length) {
                this.offset = 0;
                vectori = block.encrypt(vectori, 0);
                l = vectori.length;
            }
        }
        return ret;
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet."); //To change body of generated methods, choose Tools | Templates.
    }

}
