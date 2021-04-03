package net.siisise.security.stream;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * エンコードしながら出力担当.
 */
public class EncodeOutputStream extends FilterOutputStream {

    private final Stream cipher;

    EncodeOutputStream(Stream stream, OutputStream out) {
        super(out);
        this.cipher = stream;
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[]{(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] data) throws IOException {
        byte[] encoded = cipher.encrypt(data, 0, data.length);
        out.write(encoded);
    }

    @Override
    public void write(byte[] src, int offset, int length) throws IOException {
        byte[] encoded = cipher.encrypt(src, offset, length);
        out.write(encoded);
    }
}
