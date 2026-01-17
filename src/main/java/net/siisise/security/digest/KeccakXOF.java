
/*
 * Copyright 2026 okome.
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
package net.siisise.security.digest;

import java.io.InputStream;
import net.siisise.io.FilterInput;
import net.siisise.io.Input;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;

/**
 * 出力の拡張テスト(仮)
 */
public class KeccakXOF extends Keccak implements XOF,Input {
    Packet buff = new PacketA();

    protected KeccakXOF(int d) {
        super(d);
    }
    
    protected KeccakXOF(int c, int d) {
        super(c, d);
    }

    protected KeccakXOF(String name, int c, long d, int suffix, int suflen) {
        super(name, c, d, suffix, suflen);
    }
    
    private void gen(long len) {
        if (!buff.readable(len)) {
            
            int r = getBitBlockLength() / 8;
            long blockLen = (len - buff.size() + r - 1) / r * r;
            sponge(buff, blockLen);
        }
    }
    
    @Override
    public InputStream getInputStream() {
        return new FilterInput(this);
    }

    @Override
    public int read(byte[] buf, int offset, int length) {
        gen(length);
        return buff.read(buf, offset, length);
    }

    @Override
    public byte get() {
        gen(1);
        return buff.get();
    }

    @Override
    public long get(byte[] b, int offset, int length) {
        return read(b, offset, length);
    }

    @Override
    public byte[] toByteArray() {
        int len = getDigestLength();
        gen(len);
        byte[] tmp = new byte[len];
        read(tmp);
        return tmp;
    }

    @Override
    public Packet readPacket(long length) {
        gen(length);
        return buff.readPacket(length);
    }

    @Override
    public long length() {
        return buff.length();
    }
    
}
