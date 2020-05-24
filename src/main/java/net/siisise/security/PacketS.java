package net.siisise.security;

import java.io.InputStream;
import java.io.OutputStream;

/**
 *
 * @author okome
 */
public class PacketS {

    static final int MAXLENGTH = 0x10000;

    private class PacketIn {

        PacketIn prev;
        PacketIn next;
        byte[] data;
        int offset;
        /**
         * 実質サイズ
         */
        int length;

        PacketIn() { // NULLPACK
            prev = this;
            next = this;
            offset = 0;
            length = 0;
        }

        PacketIn(byte[] data) {
            prev = this;
            next = this;
            this.data = data;
            offset = 0;
            length = data.length;
        }

        /**
         * this = B pac = D this A // B pac C // D B.prev = C C.next = B D.prev
         * = A pac が nextのとき 自分が輪から切れる
         *
         * @param pac
         */
        void addPrev(PacketIn pac) {
            prev.next = pac;
            pac.prev.next = this;
            PacketIn pre = pac.prev;
            pac.prev = prev;
            prev = pre;
        }

        void delete() {
//            addPrev(next);
            next.prev = prev;
            prev.next = next;
        }

    }

    PacketIn nullPack = new PacketIn();

    /**
     * InputStream との違い 1バイト待たない
     */
    private class PacketBaseInputStream extends InputStream {

        PacketIn base;

        PacketBaseInputStream(PacketIn nullPac) {
            base = nullPac;
        }

        @Override
        public int read() {
            byte[] d = new byte[1];
            int len = read(d);
            if (len > 0) {
                return d[0] & 0xff;
            }
            return -1;
        }

        @Override
        public int read(byte[] b) {
            return read(b, 0, b.length);
        }

        @Override
        public int read(byte[] b, int offset, int length) {
            PacketIn n;
            int len = 0;
            while (base.next != nullPack) {
                n = base.next;
                if (length >= n.length) {
                    System.arraycopy(n.data, n.offset, b, offset, n.length);
                    length -= n.length;
                    offset += n.length;
                    len += n.length;
                    n.delete();
                } else {
                    System.arraycopy(n.data, n.offset, b, offset, length);
                    n.length -= length;
                    n.offset += length;
                    len += length;
                    return len;
                }
            }
            // 
            return len;
        }

        @Override
        public int available() {
            return size();
        }
    }

    private class PacketBaseOutputStream extends OutputStream {

        @Override
        public void write(int b) {
            write(new byte[]{(byte) b}, 0, 1);
        }

        @Override
        public void write(byte[] b) {
            write(b, 0, b.length);
        }

        /**
         * ToDo: まとめて変換してから追加してもいい
         *
         * @param src
         * @param offset
         * @param length
         */
        @Override
        public void write(byte[] src, int offset, int length) {
            byte[] d;
            while (length > MAXLENGTH) {
                d = new byte[MAXLENGTH];
                System.arraycopy(src, offset, d, 0, MAXLENGTH);
                nullPack.addPrev(new PacketIn(d));
                length -= MAXLENGTH;
                offset += MAXLENGTH;
            }
            if (length > 0) {
                d = new byte[length];
                System.arraycopy(src, offset, d, 0, length);
                nullPack.addPrev(new PacketIn(d));
            }
        }
    }
    
    PacketBaseInputStream in;
    PacketBaseOutputStream out;

    public PacketS() {
        in = new PacketBaseInputStream(nullPack);
        out = new PacketBaseOutputStream();
    }

    public InputStream getInputStream() {
        return in;
    }

    public OutputStream getOutputStream() {
        return out;
    }

/*
    public int read() {
        return in.read();
    }
*/
    public int read(byte[] b, int offset, int length) {
        return in.read(b, offset, length);
    }

    public int read(byte[] b) {
        return in.read(b);
    }

    public byte[] toByteArray() {
        byte[] d = new byte[(int) length()];
        read(d);
        return d;
    }
/*
    public void write(int b) {
        out.write(b);
    }
*/
    public void write(byte[] b, int offset, int length) {
        out.write(b, offset, length);
    }

    /**
     *
     * @param b
     */
    public void write(byte[] b) {
        out.write(b);
    }

    public long length() {
        long length = 0;
        PacketIn pc = nullPack.next;
        while (pc != nullPack) {
            length += pc.length;
            pc = pc.next;
        }
        return length;
    }

    public int size() {
        long l = length();
        if (l > Integer.MAX_VALUE) {
            return Integer.MAX_VALUE;
        }
        return (int) l;
    }
}
