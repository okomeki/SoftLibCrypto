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

/**
 * CBC-MAC
 * 
 * FIPS PUB 113
 * ISO/IEC 9797-1
 *
 * @deprecated まだ未実装、古いので使わない方がよさそ
 */
@Deprecated
public class CBCMAC implements MAC {

    Block block;
    /** ブロック出力なしMACのみ */
    MacCBC cbc;

    public CBCMAC(Block block) {
        this.block = block;
    }

    @Override
    public void init(byte[] key) {
        block.init(key);
        cbc = new MacCBC(block);
    }

    public void init(byte[][] params) {
        block.init(params);
//        cbc.init(params);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        cbc.update(src, offset, length);
    }

    @Override
    public byte[] sign() {
        return cbc.vector();
    }

    @Override
    public int getMacLength() {
        return block.getBlockLength() / 8;
    }

}
