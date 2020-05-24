package net.siisise.security.mode;

import net.siisise.security.block.Block;
import net.siisise.security.block.OneBlock;

/**
 * 拡張に拡張を重ねる
 */
public abstract class BlockMode extends OneBlock {
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
    public void init(byte[] key, byte[] iv) {
        throw new SecurityException("さぽーとしてない");
    }

    @Override
    public int getBlockLength() {
        return block.getBlockLength();
    }
}
