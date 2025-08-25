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

import net.siisise.io.Output;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.security.block.Block;

/**
 * CBC-MAC
 * 
 * FIPS PUB 113
 * ISO/IEC 9797-1
 *
 */
public class CBCMAC extends Output.AbstractOutput implements MAC {

    Block block;
    /** ブロック出力なしMACのみ */
    MacCBC cbc;
    Packet b = new PacketA();

    public CBCMAC(Block block) {
        this.block = block;
        cbc = new MacCBC(block);
    }

    @Override
    public void init(byte[] key) {
        block.init(key);
//        cbc = new MacCBC(block);
    }

    public void init(byte[][] params) {
        block.init(params);
//        cbc.init(params);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        b.write(src, offset, length);
        int l = b.size() & 0xfffffff0;
        byte[] d = new byte[l];
        b.read(d,0,l);
        cbc.update(d, 0, l);
    }

    @Override
    public byte[] sign() {
        int l = b.size();
        if ( l > 0) {
            byte[] d = new byte[16];
            b.read(d);
            cbc.update(d,0,d.length);
        }
        return cbc.vector();
    }

    @Override
    public int getMacLength() {
        return block.getBlockLength() / 8;
    }

}
