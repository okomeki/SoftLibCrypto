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

import java.io.IOException;
import java.io.OutputStream;

/**
 * 整流器.
 * 中継を減らしたいだけ. 指定長になるまでデータを貯めて、固定サイズで出力する。
 * 暗号系専用で使ってみる。
 */
public class BlockIOOutputStream extends OutputStream {

    protected final byte[] sleepBlock;
    protected final int max;
    protected final BlockIOListener listener;
    protected int offset;
    
    boolean bbmode;
    
    /**
     * 固定サイズで受け取る.
     * @param lis 受取側
     */
    public BlockIOOutputStream(BlockIOListener lis) {
        this.max = lis.getBitBlockLength() / 8;
        sleepBlock = new byte[max];
        listener = lis;
        bbmode = false;
    }
    
    /**
     * bbmode == true の場合、固定サイズの倍数で受け取れる.
     * @param lis 受け取り側
     * @param bbmode 複数ブロックをまとめて受け取ることができる場合
     */
    public BlockIOOutputStream(BlockIOListener lis, boolean bbmode) {
        this(lis);
        this.bbmode = bbmode;
    }
    
    public BlockIOOutputStream(OutputStream out, int length) {
        this(new BlockIOListener() {
            @Override
            public int getBitBlockLength() {
                return length * 8;
            }

            @Override
            public void blockWrite(byte[] src, int offset, int length) throws IOException {
                out.write(src, offset, length);
            }
            
            @Override
            public void flush() throws IOException {
                out.flush();
            }

            @Override
            public void blockFlush(byte[] buffer, int size) throws IOException {
                out.write(buffer, 0, size);
                out.flush();
            }

            @Override
            public void close() throws IOException {
                out.close();
            }
        });
    }

    /**
     * 1バイト書き
     * @param b 1バイトデータ
     * @throws IOException 
     */
    @Override
    public void write(int b) throws IOException {
        write(new byte[]{(byte) b}, 0, 1);
    }

    /**
     * データ列書き
     * @param input データ列
     * @throws IOException 
     */
    @Override
    public void write(byte[] input) throws IOException {
        write(input, 0, input.length);
    }

    /**
     * データ列書き
     * @param src データ
     * @param offset 読み位置
     * @param length サイズ
     * @throws IOException 
     */
    @Override
    public void write(byte[] src, int offset, int length) throws IOException {
        if (this.offset > 0) { // 待機データあり
            if (this.offset + length >= max) { // 出力可能 一陣合成送出
                int size = max - this.offset;
                System.arraycopy(src, offset, sleepBlock, this.offset, size);
                offset += size;
                length -= size;
                listener.blockWrite(sleepBlock, 0, max);
                this.offset = 0;
            } else { // あわせても足りないので格納
                System.arraycopy(src, offset, sleepBlock, this.offset, length);
                this.offset += length;
                return;
            }
        }

        while (length >= max) { // 複製なしで単体送出
            if ( bbmode ) {
                int ln = length / max * max;
                listener.blockWrite(src, offset, ln);
                offset += ln;
                length -= ln;
            } else {
                listener.blockWrite(src, offset, max);
                offset += max;
                length -= max;
            }
        }
        listener.flush();
        if (length > 0) { // 残機格納
            System.arraycopy(src, offset, sleepBlock, 0, length);
            this.offset = length;
        }
    }

    public int size() {
        return offset;
    }
    
    /**
     * @throws java.io.IOException
     */
    @Override
    public void flush() throws IOException {
        // パディング以外で呼ばれることもあるので何もしない
    }
    
    @Override
    public void close() throws IOException {
        // 1～max にするか、 0～ max-1にするか未定
        // 必ず呼び出す
        listener.blockFlush(sleepBlock, offset);
        listener.close();
    }

}
