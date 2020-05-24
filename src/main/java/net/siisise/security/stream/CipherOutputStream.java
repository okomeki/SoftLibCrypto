package net.siisise.security.stream;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 *
 * @author okome
 */
public class CipherOutputStream extends FilterOutputStream {
    private Cipher cipher;
    
    CipherOutputStream(Cipher cipher, OutputStream out) {
        super(out);
    }
    
    @Override
    public void write(int b) throws IOException {
        write(new byte[] {(byte)b},0,1);
    }

    @Override
    public void write(byte[] src, int offset, int length) throws IOException {
        byte[] decoded = cipher.update(src, offset, length);
        out.write(decoded);
    }
    
    @Override
    public void flush() throws IOException {
        out.flush();
    }

    @Override
    public void close() throws IOException {
        try {
            byte[] decoded = cipher.doFinal();
            out.write(decoded);
            out.flush();
            out.close();
        } catch (IllegalBlockSizeException ex) {
            throw new IOException(ex);
        } catch (BadPaddingException ex) {
            throw new IOException(ex);
        }
    }
}
