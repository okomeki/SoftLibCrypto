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

import net.siisise.lang.Bin;
import net.siisise.security.block.Block;

/**
 * ブロック単位 CBC-MAC.
 * ハッシュ用に出力を外したCBC
 */
public class MacCBC {

    private final Block block;
    private long[] vector;
    int blen;
    int vl;

    public MacCBC(Block block) {
        this.block = block;
        blen = (block.getBlockLength() + 7) / 8;
        vl = blen / 8;
        vector = new long[vl];
//        m = new PacketA();
    }

    /**
     * 
     * @return バイト長
     */
    public int getMacLength() {
        return block.getBlockLength() / 8;
    }

    public void init(byte[] key) {
        block.init(key);
    }

    /**
     * ブロック単位
     * @param src メッセージ
     * @param offset 位置
     * @param length サイズ(ブロックサイズの整数倍)
     */
    public void update(byte[] src, int offset, int length) {
        int last = offset + length;
        while (offset + blen <= last) {
            Bin.xorl(vector, src, offset, vl);
            vector = block.encrypt(vector, 0);
            offset += blen;
        }
    }

    /**
     * 結果用
     * @return vector
     */
    public byte[] vector() {
        return Bin.ltob(vector);
    }

    public byte[] sign() {
        return vector();
    }
}
