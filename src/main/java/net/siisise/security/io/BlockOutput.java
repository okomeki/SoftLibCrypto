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
package net.siisise.security.io;

import java.io.IOException;
import net.siisise.io.Output;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;

/**
 * ブロック切り入力機能.
 */
public class BlockOutput extends Output.AbstractOutput {
    
    BlockIOListener listener;
    protected Packet pac = new PacketA();
    protected int max;
    int offset;
    
    /**
     * 
     * @param listener 転送先
     */
    public BlockOutput(BlockIOListener listener) {
        this.listener = listener;
        max = (listener.getBitBlockLength() + 7) / 8;
        offset = 0;
    }
    
    /**
     * 
     * @param out 出力先
     * @param length ブロックバイト長
     */
    public BlockOutput(Output out, int byteLength) {
        this(new BlockIOListener() {
            @Override
            public int getBitBlockLength() {
                return byteLength * 8;
            }

            @Override
            public void blockWrite(byte[] src, int offset, int length) throws IOException {
                out.write(src, offset, length);
            }

            @Override
            public void flush() throws IOException {
                // Outputにflushはない
            }

            @Override
            public void blockFlush(byte[] src, int size) throws IOException {
                out.write(src, 0, size);
            }

            @Override
            public void close() throws IOException {
            }
        });
    }
/*
    @Override
    public Output put(byte[] data, int offset, int length) {
        try {
            pac.put(data, offset, length);
            byte[] block = new byte[max];
            while (pac.readable(max)) {
                pac.read(block);
                listener.blockWrite(block, 0, max);
            }
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
        return this;
    }
*/
    /**
     * コピー量を減らした実装.
     * @param data 元
     * @param offset byte offset バイト位置
     * @param length byte length バイト長
     * @return 
     */
    @Override
    public Output put(byte[] data, int offset, int length) {
        try {
            if ( this.offset + length >= max) {
                byte[] block = new byte[max];
                pac.read(block);
                int s = max - this.offset;
                System.arraycopy(data, offset, block, this.offset, s);
                offset += s;
                length -= s;
                listener.blockWrite(block, 0, max);
                this.offset = 0;
            }
            while (length >= max) {
//                byte[] t = new byte[max];
//                System.arraycopy(data, offset, t, 0, max);
//                System.out.println("bbb:" + Bin.toHex(t));
                listener.blockWrite(data, offset, max);
                offset += max;
                length -= max;
            }
        } catch (IOException ex) {
            throw new IllegalStateException(ex);
        }
        pac.put(data, offset, length);
        this.offset += length;
        return this;
    }
    
    public int size() {
        return pac.size();
    }
}
