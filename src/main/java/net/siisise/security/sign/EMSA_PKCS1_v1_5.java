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
package net.siisise.security.sign;

import java.nio.ByteBuffer;
import net.siisise.security.digest.DigestAlgorithm;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * RFC 8017 PKCS #1
 * Section 9.2. EMSA-PKCS1-v1_5
 */
public class EMSA_PKCS1_v1_5 implements EMSA {

    private final MessageDigest md;
    long len;

    EMSA_PKCS1_v1_5(MessageDigest hash) {
        md = hash;
        len = 0;
    }

    @Override
    public void update(byte[] M) {
        md.update(M);
        len += M.length;
    }

    @Override
    public void update(byte[] M, int offset, int length) {
        md.update(M, offset, length);
        len += length;
    }

    @Override
    public void update(ByteBuffer buffer) {
        len += buffer.limit() - buffer.position();
        md.update(buffer);
    }

    @Override
    public long size() {
        return len;
    }

    /**
     * 署名前.
     * アルゴリズムOIDとdigestをASN.1でくるんで整形する
     * @param emLen 最大出力バイト長限界
     * @return EM
     */
    @Override
    public byte[] encode(int emLen) {
        byte[] H = md.digest();
        len = 0;
        // DigestInfo
        DigestAlgorithm alg = new DigestAlgorithm(DigestAlgorithm.toOID(md));
        DigestInfo info = new DigestInfo(alg, H);
        byte[] T = info.encodeASN1().encodeAll();
        if ( emLen < T.length + 11 ) {
            throw new SecurityException("intended encoded message length too short");
        }
        // EM = 0x00 || 0x01 || PS || 0x00 || T
        byte[] EM = new byte[emLen];
        EM[1] = 1;
        Arrays.fill(EM, 2, emLen - T.length - 1, (byte)0xff); // PS
        System.arraycopy(T, 0, EM, EM.length - T.length, T.length);
        return EM;
    }

    @Override
    public boolean verify(byte[] M, byte[] EM, int emLen) {
        update(M);
        return verify(EM, emLen);
    }

    @Override
    public boolean verify(byte[] EM, int emLen) {
        byte[] EMd = encode(emLen);
        return Arrays.equals(EM, EMd);
    }
    
}
