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
        write(new byte[]{(byte) b}, 0, 1);
    }

    @Override
    public void write(byte[] data) throws IOException {
        byte[] decoded = cipher.decrypt(data, 0, data.length);
        out.write(decoded);
    }

    @Override
    public void write(byte[] src, int offset, int length) throws IOException {
        byte[] decoded = cipher.decrypt(src, offset, length);
        out.write(decoded);
    }

}
