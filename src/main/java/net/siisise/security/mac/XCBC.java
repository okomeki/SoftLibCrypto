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
import net.siisise.io.Output;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.block.Block;

/**
 * RFC 3566 AES-XCBC-MAC-96 MAC
 * XCBC-MAC-1
 * RFC 3664,4434 AES-XCBC-PRF-128 疑似乱数
 */
public class XCBC extends Output.AbstractOutput implements MAC {

    private final Block block;
    private MacCBC cbc;
    
    private byte[] k1;
    private byte[] k2;
    private byte[] k3;
    
    private Packet m;
    int outlen;
    
    /**
     * 
     * @param block AESなど暗号ブロック CBCは含まない
     * @param len 出力バイト長
     */
    public XCBC(Block block, int len) {
        this.block = block;
        this.outlen = len;
    }

    /**
     * 
     * @param block AES または出力サイズが決まっているBlock CBCは含まない
     */
    public XCBC(Block block) {
        this(block,(block.getBlockLength() + 7) / 8);
    }

    /**
     * 鍵1つを3つに拡張する.
     * @param key AES-XCBC-MAC-96では128bitのみ
     */
    @Override
    public void init(byte[] key) {
        block.init(key);
        int maclen = (block.getBlockLength() + 7) / 8;
        k1 = new byte[maclen];
        k2 = new byte[maclen];
        k3 = new byte[maclen];
        Arrays.fill(k1, (byte)0x01);
        Arrays.fill(k2, (byte)0x02);
        Arrays.fill(k3, (byte)0x03);
        init(block.encrypt(k1),block.encrypt(k2),block.encrypt(k3));
    }
    
    /**
     * 鍵拡張済みの場合.
     * @param keys K1, K2, K3 
     */
    public void init(byte[]... keys) {
        k1 = keys[0];
        block.init(k1);
        k2 = keys[1];
        k3 = keys[2];
        m = new PacketA();
        cbc = new MacCBC(block);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        int mlen = m.size();
        if ( mlen > 0 && mlen + length > k2.length ) {
            byte[] t = new byte[k2.length];
            m.read(t);
            int blen = k2.length - mlen;
            System.arraycopy(src, offset, t, mlen, blen);
            offset += blen;
            length -= blen;
            cbc.update(t,0,k2.length);
        }
        if ( length > k2.length ) {
            int blen = (length - 1) / k2.length * k2.length;
            cbc.update(src, offset, blen);
            offset += blen;
            length -= blen;
        }
        m.write(src, offset, length);
}

    @Override
    public byte[] sign() {
        byte[] t = new byte[k2.length];
        if ( m.size() < k2.length ) { // 10* Padding
            m.write(0x80);
            m.read(t);
            Bin.xorl(t, k3);
        } else {
            m.read(t);
            Bin.xorl(t, k2);
        }
        cbc.update(t,0,t.length);
        t = cbc.vector();
        cbc = new MacCBC(block); // 次の初期化
        return Arrays.copyOf(t, outlen);
    }

    @Override
    public int getMacLength() {
        return outlen;
    }
    
}
