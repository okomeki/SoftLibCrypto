/*
 * Copyright 2023 Siisise Net.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
