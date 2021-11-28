package net.siisise.security.mode;

import net.siisise.security.block.Block;
import net.siisise.security.block.IntBlock;

/**
 * 拡張に拡張を重ねる
 */
public abstract class BlockMode extends IntBlock {
    protected Block block;
    
    protected BlockMode(Block b) {
        block = b;
    }
    
    /**
     * パラメータは block key ivの順、省略もできるようにする.
     * @param block
     * @param key 
     */
    public void init(Block block, byte[] key) {
        this.block = block;
        block.init(key);
    }
    
    @Override
    public void init(byte[] key) {
        block.init(key);
    }

    @Override
    public void init(byte[]... params) {
        block.init(params);
    }

    @Override
    public int getBlockLength() {
        return block.getBlockLength();
    }

    static final void xor(byte[] a, byte[] b, int offset, int length) {
        for (int i = 0; i < length; i++) {
            a[i] ^= b[offset + i];
        }
    }

    static final void xor(int[] a, int[] b, int offset, int length) {
        for (int i = 0; i < length; i++) {
            a[i] ^= b[offset + i];
        }
    }
}
