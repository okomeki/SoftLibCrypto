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
package net.siisise.ietf.pkcs1;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.key.RSAPublicKey;

/**
 * RFC 8017 PKCS #1 Section 7. Encryption Schemes
 * 
 * Section 5.1.1. RSAEP, Section 5.1.2. RSADP
 * Scction 7.1.1. Step 2, 7.1.2. Step 3 EME-OAEP
 * 
 * 
 * 7.1. RSAES-OAEP
 * 
 * IEEE 1363 IFES
 * IFES-RSA
 * IFDP-RSA
 * EME-OAEP
 * 
 * RSAES-OAEP 最大 k-2hLen-2 octet
 * hLen 
 */
public class RSAES_OAEP implements RSAES {
    
    SecureRandom rnd;
    
    RSAES_OAEP() {
        try {
            rnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            // ない
        }
    }
    
    byte[] ifep(byte[] src) {
        throw new UnsupportedOperationException("まだない");
    }
    
    MessageDigest md;
    
    /**
     * RFC 8017 7.1.1. Encryption Operation
     * @param pk PublicKey 受信者のRSA公開鍵 k modulus nの長さ
     * @param m メッセージ mLen 長さ
     * @param l label (optional)
     */
    public void encrypt(RSAPublicKey pk, byte[] m, byte[] l) {
        int k = pk.getModulus().bitLength() + 7 / 8;
        int hLen = md.getDigestLength();
        int mLen = m.length;
        // 1. 長さチェック
        if ( mLen > k - 2*hLen - 2) {
            throw new SecurityException("message too long");
        }
        // 2.EME-OAEP encoding
        // a.
        if ( l == null ) {
            l = new byte[0];
        }
        byte[] lHash = md.digest(l);
        // b.
        byte[] PS = new byte[k-mLen-hLen*2-2];
        // c.
        Packet db = new PacketA();
        db.dwrite(lHash);
        db.dwrite(PS);
        db.write(0x01);
        db.write(m);
        // d.
        byte[] seed = new byte[hLen];
        rnd.nextBytes(seed);
        // e.
        byte[] dbMask = MGF(seed, k-hLen-1);
        byte[] maskedDB = Bin.xor(db.toByteArray(),dbMask);
        byte[] seedMask = MGF(maskedDB, hLen);
        byte[] maskedSeed = Bin.xor(seed,seedMask);
        
        Packet em = new PacketA();
        em.write(0x00);
        em.write(maskedSeed);
        em.write(maskedDB);
        
//        pk.rsaep(PKCS1.);
    }
    
    void oaep_encoding() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    private byte[] MGF(byte[] seed, int i) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
