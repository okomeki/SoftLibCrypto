/*
 * Copyright 2023 okome.
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
import net.siisise.security.mode.CBC;

/**
 * CBC-MAC
 * FIPS PUB 113
 * ISO/IEC 9797-1
 */
public class CBCMAC implements MAC {
    Block block;
    CBC cbc;
    
    public CBCMAC(Block block) {
        this.block = block;
    }

    @Override
    public void init(byte[] key) {
        block.init(key);
        cbc = new CBC(block);
    }
    
    public void init(byte[][] params) {
        cbc.init(params);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] sign() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getMacLength() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
