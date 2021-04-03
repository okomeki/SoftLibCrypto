package net.siisise.security.block;

import java.io.IOException;
import java.io.OutputStream;
import net.siisise.security.PacketS;
import net.siisise.security.io.BlockIOListener;

/**
 *
 */
class DecodeStream implements BlockIOListener {

    private final Block block;
    private final boolean pad;
    private final PacketS pac = new PacketS();
    private final OutputStream out;
    private final int bsize;
    private byte[] buffer;

    DecodeStream(Block b, OutputStream o, boolean pad) {
        block = b;
        this.pad = pad;
        pac.setDirect(false);
        out = o;
        bsize = block.getBlockLength() / 8;
    }

    @Override
    public int getBitBlockLength() {
        return block.getBlockLength();
    }

    @Override
    public void blockWrite(byte[] src, int offset, int length) throws IOException {
        if (pad) {
            if (buffer != null) {
                pac.write(buffer);
            }
            if (length > bsize) {
                pac.write(block.decrypt(src, offset, length - bsize));
                offset += length - bsize;
                length = bsize;
            }
            buffer = block.decrypt(src, offset);
        } else {
            pac.write(block.decrypt(src, offset, length));
        }
    }

    @Override
    public void blockFlush(byte[] buf, int size) throws IOException {
        if (pad) {
            // サイズは0かmaxのはず
            if (buffer != null) {
                int len = buffer[buffer.length - 1] & 0xff;
                // ToDo: 他のパディングもチェック
                if (len == 0) {
                    len = 256;
                }
                // len = 1 ～ 256
                if (buffer.length > len) {
                    pac.write(buffer, 0, buffer.length - len);
                }
            } else {
                throw new UnsupportedOperationException();
            }
        } else { // CFB / OFB / Stream タイプ
            byte[] dec = block.decrypt(buf, 0);
            if (buffer != null) {
                pac.write(dec, 0, size);
            }
        }
    }

    @Override
    public void flush() throws IOException {
        if (pac.size() > 0) {
            out.write(pac.toByteArray());
        }
        out.flush();
    }

    @Override
    public void close() throws IOException {
        out.close();
    }

}
