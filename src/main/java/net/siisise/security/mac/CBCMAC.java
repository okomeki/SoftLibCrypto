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
 * RFC 3566 の10*パディングなし
 */
public class CBCMAC extends Output.AbstractOutput implements MAC {

    /**
     * ブロック単位出力 パディングなしMACのみ
     */
    private final MacCBC cbc;
    Packet b = new PacketA();

    public CBCMAC(Block block) {
        cbc = new MacCBC(block);
    }

    /**
     * IVなしkey登録.
     * @param key Block (AES)鍵
     */
    @Override
    public void init(byte[] key) {
        cbc.init(key);
    }

    /**
     * IV 設定が必要なとき(MACとしては特殊).
     * @param params (AES)key, IV
     */
    public void init(byte[]... params) {
        cbc.init(params);
    }

    /**
     * ブロック単位でCBCに.
     *
     * @param src
     * @param offset
     * @param length
     */
    @Override
    public void update(byte[] src, int offset, int length) {
        b.write(src, offset, length);
        int len = b.size() & 0xfffffff0;
        byte[] d = new byte[len];
        b.read(d, 0, len);
        cbc.update(d, 0, len);
    }

//    byte[] PAD = new byte[]{(byte) 0x80};

    void padding() {
//        update(PAD);
    }

    @Override
    public byte[] sign() {
        // padding
        padding();
        int l = b.size();
        if (l > 0) {
            byte[] d = new byte[16];
            b.read(d);
            cbc.update(d, 0, d.length);
        }
        return cbc.vector();
    }

    @Override
    public int getMacLength() {
        return cbc.getMacLength();
    }

}
