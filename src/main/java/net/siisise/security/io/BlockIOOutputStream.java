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
    
    public BlockIOOutputStream(BlockIOListener lis) {
        this.max = lis.getBitBlockLength() / 8;
        sleepBlock = new byte[max];
        listener = lis;
        bbmode = false;
    }
    
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

    @Override
    public void write(int b) throws IOException {
        write(new byte[]{(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] input) throws IOException {
        write(input, 0, input.length);
    }

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

    /**
     * byte[] をint[] に変換する
     * FIPS 197 AESではsubBytes
     * @param w 出力
     * @param offset 出力位置
     * @param input 入力
     * @param inoffset 入力位置
     * @param length 出力長さ
     */
    public static void writeBig(int[] w, int offset, byte[] input, int inoffset, int length) {
        for (int i = 0; i < length; i++) {
            int of = inoffset + i * 4;
            w[offset + i] = ((input[of] & 0xff) << 24)
                    + ((input[of + 1] & 0xff) << 16)
                    + ((input[of + 2] & 0xff) << 8)
                    + (input[of + 3] & 0xff);
        }
    }

    public static void writeLittle(int[] w, int offset, byte[] input, int inoffset, int length) {
        for (int i = 0; i < length; i++) {
            int of = inoffset + i * 4;
            w[offset + i] = ((input[of + 3] & 0xff) << 24)
                    + ((input[of + 2] & 0xff) << 16)
                    + ((input[of + 1] & 0xff) << 8)
                    + (input[of] & 0xff);
        }
    }

    public static void writeBig(long[] w, int offset, byte[] input, int inoffset, int length) {
        for (int i = 0; i < length; i++) {
            int of = inoffset + i * 8;
            w[offset + i] = (((long) input[of] & 0xff) << 56)
                    + (((long) input[of + 1] & 0xff) << 48)
                    + (((long) input[of + 2] & 0xff) << 40)
                    + (((long) input[of + 3] & 0xff) << 32)
                    + (((long) input[of + 4] & 0xff) << 24)
                    + ((input[of + 5] & 0xff) << 16)
                    + ((input[of + 6] & 0xff) << 8)
                    + (input[of + 7] & 0xff);
        }
    }

    public static void writeLittle(long[] w, int offset, byte[] input, int inoffset, int length) {
        for (int i = 0; i < length; i++) {
            int of = inoffset + i * 8;
            w[offset + i] = (((long) (input[of + 7] & 0xff)) << 56)
                    + (((long) (input[of + 6] & 0xff)) << 48)
                    + (((long) (input[of + 5] & 0xff)) << 40)
                    + (((long) (input[of + 4] & 0xff)) << 32)
                    + (((long) (input[of + 3] & 0xff)) << 24)
                    + ((input[of + 2] & 0xff) << 16)
                    + ((input[of + 1] & 0xff) << 8)
                    + (input[of] & 0xff);
        }
    }

}
