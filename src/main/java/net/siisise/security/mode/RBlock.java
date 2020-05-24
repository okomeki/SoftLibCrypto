package net.siisise.security.mode;

import net.siisise.security.block.Block;
import net.siisise.security.mode.BlockMode;

/**
 *
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
    
}
