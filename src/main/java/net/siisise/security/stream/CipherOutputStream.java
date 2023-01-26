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
package net.siisise.security.stream;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 *
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
