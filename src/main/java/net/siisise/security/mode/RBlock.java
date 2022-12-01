package net.siisise.security.mode;

import net.siisise.security.block.Block;

/**
 * 暗号化と復号化を逆にするフィルタ.
 */
public class RBlock extends BlockMode {
    
    public RBlock(Block block) {
        super(block);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        return block.decrypt(src, offset);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return block.encrypt(src, offset);
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        return block.decrypt(src, offset);
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        return block.encrypt(src, offset);
    }
    
    @Override
    public long[] encrypt(long[] src, int offset) {
        return block.decrypt(src, offset);
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        return block.encrypt(src, offset);
    }
    
}
