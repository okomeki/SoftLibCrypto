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
import net.siisise.io.LittleBitPacket;
import net.siisise.io.Output;

/**
 * ブロック切り機能. ビット単位入力に対応したもの.
 */
public class BitBlockOutput extends BlockOutput {

    public BitBlockOutput(BlockIOListener listener) {
        super(listener);
        pac = new LittleBitPacket();
    }

    @Override
    public Output put(byte[] data, int offset, int length) {
        pac.put(data, offset, length);
        out();
        return this;
    }

    public void writeBit(byte[] data, long bitOffset, long bitLength) {
        ((LittleBitPacket) pac).writeBit(data, bitOffset, bitLength);
        out();
    }
    
    public void writeBit(int data, int bitLength) {
        ((LittleBitPacket)pac).writeBit(data, bitLength);
        out();
    }
    
    private void out() {
        while (pac.readable(max)) {
            byte[] d = new byte[max];
            pac.read(d);
            try {
                listener.blockWrite(d, 0, max);
            } catch (IOException ex) {
                throw new IllegalStateException(ex);
            }
        }
    }

    public long bitLength() {
        return ((LittleBitPacket)pac).bitLength();
    }
}
