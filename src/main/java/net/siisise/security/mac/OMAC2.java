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

import net.siisise.math.GF;
import net.siisise.security.block.Block;

/**
 * OMAC2
 * K1は変わらないらしい
 * k2 が L^-1っぽくなる.
 * http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/omac.html
 */
public class OMAC2 extends CMAC {
    
    public OMAC2() {
        super();
    }
    
    public OMAC2(byte[] key) {
        init(key);
    }
    
    public OMAC2(Block block) {
        super(block);
    }

    @Override
    void initk(byte[] L, GF gf) {
        k1 = gf.x(L);
        k2 = gf.r(L);
    }
}
