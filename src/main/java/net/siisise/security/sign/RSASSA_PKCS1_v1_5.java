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

import java.security.MessageDigest;
import java.util.Arrays;
import net.siisise.security.digest.SHA1;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;

/**
 * 互換性のためにあるらしい.
 * PKCS #7 RFC 2315
 * @deprecated ふるい
 */
public class RSASSA_PKCS1_v1_5 extends RSASSA {
    
    /**
     * 省略時 SHA-1 を使用(非推奨)
     */
    public RSASSA_PKCS1_v1_5() {
        this(new SHA1());
    }

    /**
     * @param md ダイジェストを直接指定
     */
    public RSASSA_PKCS1_v1_5(MessageDigest md) {
        emsa = new EMSA_PKCS1_v1_5(md);
    }
    
    @Override
    public byte[] sign(RSAMiniPrivateKey key) {
        int k = (key.getModulus().bitLength() + 7) / 8;
        byte[] EM = emsa.encode(k);
        return key.rsasp1(EM, k);
    }

    @Override
    public boolean verify(RSAPublicKey pub, byte[] S) {
        int k = (pub.getModulus().bitLength() * + 7) / 8;
        if (S.length != k) {
            throw new SecurityException("invalid signature");
        }
        byte[] EM;
        try {
            EM = pub.rsavp1(S,k);
        } catch (SecurityException e) {
            if ( e.getMessage().equals("signature representative out of range")) {
                throw new SecurityException("invalid signature");
            } else if ( e.getMessage().equals("integer too large")) {
                throw new SecurityException("invalid signature");
            }
            throw new SecurityException();
        }
        byte[] EMd;
        try {
            EMd = emsa.encode(k);
        } catch (SecurityException e) {
            if (e.getMessage().equals("message too long")) {
                throw new SecurityException("message too long");
            } else if ( e.getMessage().equals("intended encoded message length too short")) {
                throw new SecurityException("RSA modulus too short");
            }
            throw new SecurityException();
        }
        return Arrays.equals(EM, EMd);
    }
    
}
