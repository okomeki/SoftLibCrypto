package net.siisise.security.block;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import net.siisise.security.io.BlockIOListener;
import net.siisise.security.io.BlockIOOutputStream;
import net.siisise.security.PacketS;

/**
 * 暗号、復号化するストリームを作る。
 * パディングするので送信タイミングはずれることがある。
 */
class EncodeStream implements BlockIOListener {

    private final Block block;
    private final OutputStream out;
    private final PacketS pac;
    private final boolean padding;

    EncodeStream(Block b, OutputStream out, boolean pad) {
        block = b;
        this.out = out;
        padding = pad;
        pac = new PacketS();
        pac.setDirect(true);
    }

    @Override
    public int getBitBlockLength() {
        return block.getBlockLength();
    }

    @Override
    public void blockWrite(byte[] src, int offset, int length) throws IOException {
        byte[] enc = block.encrypt(src, offset, length);
        pac.write(enc);
    }

    @Override
    public void flush() throws IOException {
        if (pac.length() > 0l) {
            out.write(pac.toByteArray());
        }
    }

    /**
     * PKCS5/7のPadding(仮).
     * サイズがずれていたら勝手につける
     *
     * @param size 0以上maxまでくらい
     * @throws IOException
     */
    @Override
    public void blockFlush(byte[] src, int size) throws IOException {
//        flush();
        if (padding) {
            //byte[] pad = new byte[src.length - size];
            Arrays.fill(src, size, src.length, (byte) (getBitBlockLength() / 8 - size));
            byte[] enc = block.encrypt(src, 0);
            pac.write(enc);
        } else {  // FBタイプ
            byte[] enc = block.encrypt(src, 0);
            pac.write(enc, 0, size);
        }
        flush();
        out.flush();
    }

    @Override
    public void close() throws IOException {
        out.close();
    }

    /**
     * Encode Output.
     * PKCS#5 とか PKCS#7っぽいpaddingがつく版
     *
     * @param block モード設定済み暗号法
     * @param out 出力先
     * @param pad
     * @return
     */
    public static OutputStream encodePadStream(Block block, OutputStream out, boolean pad) {
        return new BlockIOOutputStream(new EncodeStream(block, out, pad), true);
    }

    /**
     * Decode Output.
     * ブロック ファイル 実サイズ
     *
     * @param block
     * @param out
     * @param pad
     * @return
     */
    public static BlockIOOutputStream decodePadStream(Block block, OutputStream out, boolean pad) {
        return new BlockIOOutputStream(new DecodeStream(block, out, pad), true);
    }

    static class DecodeInputBlock extends InputStream {

        private final PacketS decoded = new PacketS();
        private final PacketS pac = new PacketS();
        private final int blockLen;
        private final Block block;
        private final InputStream in;
        private final boolean pad;
        private boolean eof = false;
        private boolean eof2 = false;

        DecodeInputBlock(Block block, InputStream in, boolean pad) {
            this.block = block;
            blockLen = block.getBlockLength() / 8;
            this.in = in;
            this.pad = pad;
        }

        @Override
        public int read() throws IOException {
            byte[] a = new byte[1];
            int l = read(a, 0, 1);
            return (l == 1) ? (a[0] & 0xff) : -1;
        }

        @Override
        public int read(byte[] buf, int offset, int length) throws IOException {
            int ps = decoded.size();
            if (length <= ps) {
                decoded.read(buf, offset, length);
                return length;
            } else if (ps > 0) {
                decoded.read(buf, offset, ps);
                offset += ps;
                length -= ps;
            }
            if (eof2 && ps == 0) {
                return -1;
            }
            int l = ((length + blockLen * 2 - 1) / blockLen) * blockLen;
            byte[] buff = new byte[l];
            int buffsize = 0;
            int decoff = 0;

            // pac残量処理
            int len = pac.size();
            if (len > 0) {
                buffsize = l < len ? l : len;
                pac.read(buff, 0, buffsize);
            }

            while (l > buffsize && !eof) {
                len = in.read(buff, buffsize, l - buffsize);
                if (len < 0) {
                    eof = true;
                } else {
                    buffsize += len;
                }
            }
            while (decoff <= buffsize - blockLen * 2) { // EOF判定の不要な範囲
                int ds = (buffsize - blockLen) / blockLen * blockLen;
                byte[] decc = block.decrypt(buff, decoff, ds - decoff);
                if (length >= decc.length) {
                    System.arraycopy(decc, 0, buf, offset + decoff, decc.length);
                    decoff += decc.length;
                    length -= decc.length;
                } else {
                    System.arraycopy(decc, 0, buf, offset + decoff, length);
                    decoded.write(decc, length, decc.length - length);
                    //decoded.read(buf, offset + decoff, length);
                    ps -= blockLen - length;
                    decoff += blockLen;
                    length = 0;
                }
            }
//                System.out.println("buffsize:"+buffsize+" decoff:" +decoff+ " ながさ:" + length);
            if (!eof) {
                pac.write(buff, decoff, buffsize - decoff);
            } else {
                byte[] decc = block.decrypt(buff, decoff);
                int lastlen = pad ? blockLen - (decc[blockLen - 1] & 0xff) : blockLen;
                decoded.write(decc, 0, lastlen);
                eof2 = true;
            }
            if (decoded.size() > 0 && length > 0) {
                int min = decoded.size() > length ? length : decoded.size();
                decoded.read(buf, offset + decoff, min);
                decoff += min;
            }

            return ps + decoff;
        }

    }

    /**
     * InputStream + decode. ファイル = blockサイズ
     *
     * @param block
     * @param in
     * @param pad まだパッドありのみ
     * @return
     */
    public static InputStream decodePadStream(Block block, InputStream in, boolean pad) {
        return new DecodeInputBlock(block, in, pad);
    }
}
