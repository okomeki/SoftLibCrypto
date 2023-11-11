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
package net.siisise.security.mac;

import net.siisise.security.block.Block;

/**
 * Kaoru Kurosawa, Tetsu Iwata、TMAC: Two-Key CBC MAC、2004年、IEICE Trans. Fundamentals, Vol. E87-A (1), pp. 46-52. 
 * @deprecated まだ未実装、古いので使わない方がよさそ
 */
public class TMAC implements MAC {
    private final Block block;
    MacCBC cbc;
    byte[] k2;
    
    public TMAC(Block block) {
        this.block = block;
        cbc = new MacCBC(block);
    }
    
    @Override
    public void init(byte[] key) {
        byte[] k1 = new byte[key.length];
        block.init(k1);
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getMacLength() {
        return block.getBlockLength() / 8;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] sign() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
