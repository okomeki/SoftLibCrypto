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
package net.siisise.security.stream;

/**
 * RC4 cipher suite.
 * RFC 6229 Test Vectors
 * @deprecated 規格はRFC 7465で廃止,まだない
 */
@Deprecated
public class RC4 implements Stream {
    /**
     * 処理bit単位
     */
    //final int n = 8;
    byte[] S = new byte[256];
    byte[] K = new byte[256];
    
    int i;
    int j;

    public void init(byte[]... keyandparam) {
        K = keyandparam[0];
        ksa();
        i = -1;
        j = 0;
    }
    
    void ksa() {
        // t = 1
        for ( int ki = 0; ki < 256; ki++) {
            S[ki] = (byte)ki;
        }
        int kj = 0;
        for ( int ki = 0; ki < 256; ki++) {
            kj = (kj + S[ki] + K[ki % K.length]) & 0xff;
            byte tmp = S[ki]; S[ki] = S[kj]; S[kj] = tmp; 
        }
    }
/*
    void prga(byte[] d, int of, int len) {
        len += of;
        while ( of < len ) {
            i = i + 1 & 0xff;
            j = j + S[i] & 0xff;
            byte tmp = S[i]; S[i] = S[j]; S[j] = tmp;
            byte ZZ = (byte) (S[i] + S[j]);
            d[of++] ^= ZZ;
        }
    }
*/
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        byte[] enc = new byte[length];
        int eoff = 0;
        while ( eoff < length ) {
            i = i + 1 & 0xff;
            j = j + S[i] & 0xff;
            byte tmp = S[i]; S[i] = S[j]; S[j] = tmp;
            byte ZZ = (byte) (S[i] + S[j]);
            enc[eoff] = (byte) (src[offset + eoff] ^ ZZ);
            eoff++;
        }
        return enc;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }
}
