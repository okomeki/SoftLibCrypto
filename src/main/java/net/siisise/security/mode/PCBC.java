package net.siisise.security.mode;

import net.siisise.security.block.Block;

/**
 * Propagating Cipher Block Chaning (PCBC).
 * Wikipediaより
 * BlockModeのみ
 * ブロックの前後差し替えが可能なので利用されない。
 */
public class PCBC extends BlockMode {

    byte[] vector;

    public PCBC(Block b) {
        super(b);
    }

    @Override
    public void init(byte[]... key) {
        byte[][] nkey = new byte[key.length - 1][];
        System.arraycopy(key,0,nkey,0,key.length - 1);
        super.init(nkey);
        byte[] iv = key[key.length - 1];
        vector = new byte[block.getBlockLength() / 8];
        System.arraycopy(iv, 0, vector, 0, vector.length > iv.length ? iv.length : vector.length);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        for (int i = 0; i < vector.length; i++) {
            vector[i] ^= src[offset + i];
        }
        byte[] ret = block.encrypt(vector, 0);
        for (int i = 0; i < vector.length; i++) {
            vector[i] = (byte) (src[offset + i] ^ ret[i]);
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        byte[] ret = block.decrypt(src, offset);
        for (int i = 0; i < vector.length; i++) {
            ret[i] ^= vector[i];
        }
        for (int i = 0; i < vector.length; i++) {
            vector[i] = (byte) (ret[i] ^ src[offset + i]);
        }
        return ret;
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

}
