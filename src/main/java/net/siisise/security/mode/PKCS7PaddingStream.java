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
package net.siisise.security.mode;

import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.security.block.Block;
import net.siisise.security.stream.Stream;

/**
 * ブロックでなくてよかった.
 * 2048 bit ぐらいまでの暗号に使えるのかな.
 * ストリームで中間のパディングを入れるのか入れないのか.
 * 1バイト単位で送信する場合など Stream暗号と同じことをしたいとき1回単位で送信可能にする.
 */
public class PKCS7PaddingStream implements Stream {
    private final Block block;
    private int len;

    public PKCS7PaddingStream(Block block) {
        this.block = block;
    }

    /**
     * 初期化系
     * @param params 
     */
    public void init(byte[]... params) {
        block.init(params);
        len = block.getBlockLength() / 8;
    }
    
    /**
     * ブロック単位で分割する.
     * 毎ブロックにpadding が必ず入る.
     * 最後は埋める.
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        Packet p = new PacketA();
        byte[] b = new byte[len];
        while ( length - offset >= len ) {
            System.arraycopy(src, offset, b, 0, len - 1);
            b[len - 1] = 1;
            
            p.dwrite(block.encrypt(b, 0));
            offset += len - 1;
        }
        
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    /**
     * 
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    public byte[] doFinalEncrypt(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
