package net.siisise.security.mode;

import net.siisise.security.block.Block;

/**
 * Cipher Block Chaining.
 * iv は 0 でいいがJavaのは必須?
 */
public class CBC extends BlockMode {

    private int[] vectori;

    public CBC(Block block) {
        super(block);
        vectori = new int[block.getBlockLength() / 32];
    }

    @Override
    public void init(byte[]... params) {
        byte[] iv;
        
        byte[][] params2 = params;
        byte[] vector = new byte[block.getBlockLength() / 8];
        if ( params.length > 1 ) {
            iv = params[params.length-1];
            params2 = new byte[params.length-1][];
            System.arraycopy(params, 0, params2, 0, params.length - 1);
            System.arraycopy(iv, 0, vector, 0, iv.length);
        }
        block.init(params2);
        vectori = btoi(vector);
    }

    @Override
    public void init(Block block, byte[] key) {
        super.init(block, key);
        vectori = new int[block.getBlockLength() / 32];
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        int vl = vectori.length;
        int[] isrc = new int[vl];
        btoi(src, offset, isrc, vl);
        xor(vectori, isrc, 0, vl);
        return itob(vectori = block.encrypt(vectori,0));
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        xor(vectori, src, offset, vectori.length);
        int[] ret = block.encrypt(vectori,0);
        // 複製が必要かもしれない
        System.arraycopy(ret, 0, vectori, 0, ret.length);
        return ret;
    }

    /**
     * byte to int
     * @param src 平文 plane text
     * @param offset
     * @param length
     * @return 暗号列
     */

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int vl = vectori.length;
        byte[] ret = new byte[length];
        int o4 = 0;
        while (o4 < length) {
            // XOR
            for (int i = 0; i < vl; i++, offset+=4) {
                vectori[i] ^= (src[offset  ]         << 24)
                           | ((src[offset+1] & 0xff) << 16)
                           | ((src[offset+2] & 0xff) <<  8)
                           |  (src[offset+3] & 0xff);
            }

            vectori = block.encrypt(vectori, 0);
            
            for (int i = 0; i < vl; i++, o4+= 4) {
                ret[o4  ] = (byte) (vectori[i] >> 24);
                ret[o4+1] = (byte) (vectori[i] >> 16);
                ret[o4+2] = (byte) (vectori[i] >>  8);
                ret[o4+3] = (byte)  vectori[i]       ;
            }
        }
        return ret;
    }

    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        int vl = vectori.length;
        int[] ret = new int[length];
        int roffset = 0;

        while (length > 0) {
//          XOR
            for (int i = 0; i < vl; i++) {
                vectori[i] ^= src[offset++];
            }
            vectori = block.encrypt(vectori, 0);
            // 複製が必要かもしれない
            System.arraycopy(vectori, 0, ret, roffset, vl);
            length -= vl;
            roffset += vl;
        }
        return ret;
    }

    /**
     * 
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        int[] n = new int[vectori.length];
        btoi(src, offset, n, vectori.length);
        //System.arraycopy(src, offset, n, 0, vectori.length);
        int[] ret = block.decrypt(n, 0);
        // 複製が必要かもしれない
        xor(ret,vectori,0,vectori.length);
//        for (int i = 0; i < vector.length; i++) {
//            ret[i] ^= vector[i];
//        }
        vectori = n;
        return itob(ret);
    }

    /**
     * byte to int decrypt
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int l4 = length/4;
        int[] isrc = new int[l4];
        
        for (int i = 0; i < l4; i ++) {
            isrc[i] = ( src[offset  ]         << 24)
                    | ((src[offset+1] & 0xff) << 16)
                    | ((src[offset+2] & 0xff) <<  8)
                    |  (src[offset+3] & 0xff);
            offset+=4;
        }

        byte[] ret = new byte[length];
        offset = 0;
        int bl = vectori.length;
        int bl4 = bl * 4;
        int[] re;

        re = block.decrypt(isrc, 0);
        for (int i = 0; i < bl; i++) {
            int x = re[i] ^ vectori[i];
            ret[offset  ] = (byte)(x >> 24);
            ret[offset+1] = (byte)(x >> 16);
            ret[offset+2] = (byte)(x >>  8);
            ret[offset+3] = (byte) x;
            offset+=4;
        }

        int voffset = 0;
        //length -= bl4;

        while (offset < length) {
            re = block.decrypt(isrc, offset / 4);
            for (int i = 0; i < bl; i++) {
                int x = re[i] ^ isrc[voffset++];
                ret[offset  ] = (byte)(x >> 24);
                ret[offset+1] = (byte)(x >> 16);
                ret[offset+2] = (byte)(x >>  8);
                ret[offset+3] = (byte) x;
                offset+=4;
            }
        //    length -= bl4;
//            offset += vl;
        }
        btoi(ret,offset-bl4,vectori,bl);
        System.arraycopy(isrc, voffset, vectori, 0, bl);
        return ret;
    }

    /**
     * 
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int[] ret = new int[length];
        int roffset = 0;
        int bl = vectori.length;
        int[] re;

        re = block.decrypt(src, offset);
//        xor(ret,vector,0,vl);
        for (int i = 0; i < bl; i++) {
            ret[i] = re[i] ^ vectori[i];
        }

        int voffset = offset;
        offset += bl;
        roffset += bl;
        length -= bl;

        while (length > 0) {
            re = block.decrypt(src, offset);
            for (int i = 0; i < bl; i++) {
                ret[roffset++] = re[i] ^ src[voffset++];
            }
            length -= bl;
            offset += bl;
        }
        System.arraycopy(src, voffset, vectori, 0, bl);
        return ret;
    }

    /**
     * 
     * @param src
     * @param offset
     * @return 
     */
    @Override
    public int[] decrypt(int[] src, int offset) {
        int[] n = new int[vectori.length];
        System.arraycopy(src, offset, n, 0, vectori.length);
        int[] ret = block.decrypt(n, 0);
        // 複製が必要かもしれない
//        xor(ret,vectori,0,vectori.length);
        for (int i = 0; i < vectori.length; i++) {
            ret[i] ^= vectori[i];
        }
        vectori = n;
        return ret;
    }
}
