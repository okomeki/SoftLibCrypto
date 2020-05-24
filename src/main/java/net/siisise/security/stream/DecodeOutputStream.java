package net.siisise.security.stream;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * デコードしながら出力担当.
 */
public class DecodeOutputStream extends FilterOutputStream {

    private final Stream cipher;
    
    public DecodeOutputStream(Stream stream, OutputStream out) {
        super(out);
        this.cipher = stream;
    }

    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte)b},0,1);
    }
    
    @Override
    public void write(byte[] data) throws IOException {
        byte[] decoded = cipher.decrypt(data,0,data.length);
        out.write(decoded);
    }
    
    @Override
    public void write(byte[] src, int offset, int length) throws IOException {
        byte[] decoded = cipher.decrypt(src, offset, length);
        out.write(decoded);
    }
    
}
