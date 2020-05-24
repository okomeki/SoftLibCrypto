package net.siisise.security.stream;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * エンコードしながら入力担当.
 */
public class EncodeInputStream extends FilterInputStream {
    

    private final Stream cipher;
    
    public EncodeInputStream(Stream cipher, InputStream in) {
        super(in);
        this.cipher = cipher;
    }
    
    @Override
    public int read() throws IOException {
        byte[] tmp = new byte[1];
        int r = read(tmp);
        if ( r <= 0) return -1;
        return tmp[0] & 0xff;
    }
    
    @Override
    public int read(byte[] data) throws IOException {
        return read(data,0,data.length);
    }
    
    @Override
    public int read(byte[] data, int offset, int length) throws IOException {
        byte[] tmp = new byte[length];
        int r = in.read(tmp);
        if ( r <= 0 ) return r;
        byte[] encoded = cipher.encrypt(tmp, r, r);
        System.arraycopy(encoded, 0, data, offset, r);
        return r;
    }
}
