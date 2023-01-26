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
package net.siisise.security.io;

/**
 * IOExceptionが発生しない版
 * OutputStreamは使えない
 */
public class BlockOutputStream extends BlockIOOutputStream {
    
    public BlockOutputStream(BlockListener lis) {
        super(lis);
    }
    
    @Override
    public void write(int b) {
        write(new byte[]{(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] input) {
        write(input, 0, input.length);
    }

    @Override
    public void write(byte[] src, int offset, int length) {
        if (this.offset > 0) { // 待機データあり
            if (this.offset + length >= max) { // 出力可能 一陣合成送出
                int size = max - this.offset;
                System.arraycopy(src, offset, sleepBlock, this.offset, size);
                offset += size;
                length -= size;
                ((BlockListener)listener).blockWrite(sleepBlock, 0, max);
                this.offset = 0;
            } else { // あわせても足りないので格納
                System.arraycopy(src, offset, sleepBlock, this.offset, length);
                this.offset += length;
                return;
            }
        }

        while (length >= max) { // 複製なしで単体送出
            ((BlockListener)listener).blockWrite(src, offset, max);
            offset += max;
            length -= max;
        }
        ((BlockListener)listener).flush();
        if (length > 0) { // 残機格納
            System.arraycopy(src, offset, sleepBlock, 0, length);
            this.offset = length;
        }
    }
    
    @Override
    public void flush() {}

}
