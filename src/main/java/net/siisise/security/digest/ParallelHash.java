/*
 * Copyright 2023 okome.
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

import net.siisise.io.Packet;
import net.siisise.io.PacketA;

/**
 * NIST SP 800-185 6 ParallelHash
 * @deprecated 未テスト
 */
public class ParallelHash extends cSHAKE implements XOF {
    int b;
    int L;
    Packet z;
    int size;
    cSHAKE shake;
    int n;

    /**
     * 
     * @param c 暗号強度 128 または 256
     * @param b block size
     * @param l ハッシュ出力バイト長 200 まで
     * @param S 付加文字
     */
    public ParallelHash(int c, int b, int l, String S) {
        super(c, l, "ParallelHash", S);
        this.b = b;
        this.L = l;
        z = new PacketA();
        z.write(SHA3Derived.left_encode(b));
        size = b;
        shake = new cSHAKE(c,c*2,"","");
        byte[] zb = z.toByteArray();
        super.engineUpdate(zb, 0, zb.length);
        n = 0;
    }
    
    @Override
    public void engineUpdate(byte[] src, int offset, int length) {
        while ( size <= length ) {
                shake.update(src, offset, size);
                length -= size;
                offset += size;
                byte[] dj = shake.digest();
                super.engineUpdate(dj, 0, dj.length);
                size = b;
                n++;
        }
        if ( length > 0 ) {
            shake.update(src,offset,length);
            size -= length;
        }
    }
    
    /**
     *
     * @return 
     */
    @Override
    public byte[] engineDigest() {
        if ( size < b) {
            byte[] dj = shake.digest();
            super.engineUpdate(dj, 0, dj.length);
            n++;
            size = b;
        }
        z.write(SHA3Derived.right_encode(n));
        z.write(SHA3Derived.right_encode(L));
        byte[] zb = z.toByteArray();

        n = 0;
        super.engineUpdate(zb, 0, zb.length);
        return super.engineDigest();
    }
    
}
