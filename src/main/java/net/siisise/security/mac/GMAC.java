/*
 * Copyright 2025 okome.
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

import net.siisise.io.Output;
import net.siisise.security.block.Block;

/**
 *
 */
public class GMAC extends Output.AbstractOutput implements MAC {
    private Block block;
    GHASH hash;

    /**
     * 
     * @param block 128bit ブロック暗号
     */
    public GMAC(Block block) {
        this.block = block;
        hash = new GHASH();
    }

    /**
     * GHASHの初期化に必要なAESの鍵.
     * @param key 
     */
    @Override
    public void init(byte[] key) {
        block.init(key);
        long[] H = block.encrypt(new long[block.getBlockLength() / 64]);
        hash.init(H);
    }

    /**
     * ブロック長そのまま(仮).
     * @return 
     */
    @Override
    public int getMacLength() {
        return block.getBlockLength() / 8;
    }

    /**
     * AADの入力.
     * @param src AAD
     * @param offset
     * @param length 
     */
    @Override
    public void update(byte[] src, int offset, int length) {
        hash.update(src, offset, length);
    }

    @Override
    public byte[] sign() {
        hash.blockClose(); // AADの終了
        // 本文なし
        return hash.sign();
    }
    
}
