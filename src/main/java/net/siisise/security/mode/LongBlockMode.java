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
import net.siisise.security.block.LongBlock;

/**
 *
 */
public abstract class LongBlockMode extends LongBlock {
    protected Block block;
    
    protected LongBlockMode(Block b) {
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
    
    /**
     * 初期化
     * 
     * @param params 外側が後ろ
     */
    @Override
    public void init(byte[]... params) {
        block.init(params);
    }

    @Override
    public int getBlockLength() {
        return block.getBlockLength();
    }
    
    /**
     * 必要なパラメータの長さ
     * 後ろが外側用のパラメータ長.
     * @return 
     */
    @Override
    public int[] getParamLength() {
        return new int[] {block.getBlockLength(), getBlockLength() };
    }
}
