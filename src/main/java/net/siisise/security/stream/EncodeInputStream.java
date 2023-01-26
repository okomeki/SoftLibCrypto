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
        if (r <= 0) {
            return -1;
        }
        return tmp[0] & 0xff;
    }

    @Override
    public int read(byte[] data) throws IOException {
        return read(data, 0, data.length);
    }

    @Override
    public int read(byte[] data, int offset, int length) throws IOException {
        byte[] tmp = new byte[length];
        int r = in.read(tmp);
        if (r <= 0) {
            return r;
        }
        byte[] encoded = cipher.encrypt(tmp, r, r);
        System.arraycopy(encoded, 0, data, offset, r);
        return r;
    }
}
