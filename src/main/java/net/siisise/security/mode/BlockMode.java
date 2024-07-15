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

import java.util.Arrays;
import net.siisise.security.block.Block;
import net.siisise.security.block.IntBlock;

/**
 * 拡張に拡張を重ねる
 */
public abstract class BlockMode extends IntBlock {
    protected Block block;
    
    protected BlockMode(Block b) {
        block = b;
    }
    
    /**
     * 暗号の差し替えと初期化.
     * パラメータは block key ivの順、省略もできるようにする.
     * 複数モードを重ねてかけることも可能な構造.
     * @param block 内側の暗号ブロックを差し替える
     * @param params 内側の要素から初期化パラメータを順にならべたもの
     */
    public void init(Block block, byte[]... params) {
        this.block = block;
        init(params);
    }
    
    /**
     * 初期化
     * 
     * @param params 内側の暗号のパラメータ + 外側のMODEのパラメータ 外側が後ろ
     */
    @Override
    public void init(byte[]... params) {
        block.init(params);
    }

    /**
     * 内側に渡すパラメータを生成する内部処理.
     * @param c 減らすパラメータ数
     * @param params パラメータ
     * @return c個減らされたパラメータ
     */
    protected byte[][] in(int c, byte[]... params) {
        byte[][] np = new byte[params.length - c][];
        System.arraycopy(params, 0, np, 0, np.length);
        return np;
    }

    /**
     * ビット長.
     * パディングなどある場合は外?
     * @return  ビット長
     */
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
        int[] pl = block.getParamLength();
        int[] np = Arrays.copyOf(pl, pl.length + 1);
        np[np.length - 1] = getBlockLength();
        return np;
    }
}
