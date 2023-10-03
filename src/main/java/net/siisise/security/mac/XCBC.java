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

import java.util.Arrays;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.block.Block;
import net.siisise.security.mode.CBC;

/**
 * RFC 3566 AES-XCBC-MAC-96 MAC
 * XCBC-MAC-1
 * RFC 3664,4434 AES-XCBC-PRF-128 疑似乱数
 * @deprecated まだ
 */
public class XCBC implements MAC {

    private final Block block;
    private Block cbc;
    
    private byte[] k1;
    private byte[] k2;
    private byte[] k3;
    
    private Packet m;
    int len;
    
    public XCBC(Block block, int len) {
        this.block = block;
        this.len = len;
    }
    
    public XCBC(Block block) {
        this(block,16);
    }

    /**
     * 
     * @param key AES-XCBC-MAC-96では128bitのみ
     */
    @Override
    public void init(byte[] key) {
        block.init(key);
        int len = getMacLength();
        k1 = new byte[len];
        k2 = new byte[len];
        k3 = new byte[len];
        Arrays.fill(k1, (byte)0x01);
        Arrays.fill(k2, (byte)0x02);
        Arrays.fill(k3, (byte)0x03);
        k1 = block.encrypt(k1);
        k2 = block.encrypt(k2);
        k3 = block.encrypt(k3);
        init(k1,k2,k3);
    }
    
    public void init(byte[]... keys) {
        k1 = keys[0];
        block.init(k1);
        cbc = new CBC(block);
        k2 = keys[1];
        k3 = keys[2];
        m = new PacketA();
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        m.write(src, offset, length);
        if ( m.size() > len ) {
            byte[] t = new byte[len];
            do {
                m.read(t);
                cbc.encrypt(t);
            } while ( m.size() > len );
        }
    }

    @Override
    public byte[] sign() {
        byte[] t = new byte[16];
        if ( m.size() < 16 ) {
            m.write(0x80);
            m.write(new byte[16 - m.size()]);
            m.read(t);
            Bin.xorl(t, k2);
        } else {
            m.read(t);
            Bin.xorl(t, k3);
        }
        return Arrays.copyOf(cbc.encrypt(t), len);
    }

    @Override
    public int getMacLength() {
        return (block.getBlockLength() + 7) / 8;
    }
    
}
