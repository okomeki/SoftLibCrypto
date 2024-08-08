/*
 * Copyright 2024 okome.
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
package net.siisise.ietf.pkcs5;

import java.security.MessageDigest;
import java.util.Arrays;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.security.digest.MD5;

/**
 * OpenSSL の PBKDF1 長さ無制限版
 */
public class OpenSSLPBKDF1 extends PBKDF1 {
    
//    private final MessageDigest md;

    /**
     * 長さ固定されてないsalt
     */
//    private byte[] salt;
//    int c;
    
    public OpenSSLPBKDF1() {
        super(new MD5());
    }
    
    public OpenSSLPBKDF1(MessageDigest digest) {
        super(digest);
    }
    
    public void init(byte[] salt) {
        init(salt, 1);
    }

    /**
     * 
     * @param password
     * @param salt 8バイトに制限して利用
     * @param c 基本1回のみ 拡張利用可能
     * @param dkLen
     * @return 
     */
    @Override
    public byte[] pbkdf(byte[] password, byte[] salt, int c, int dkLen) {
        byte[] s = Arrays.copyOf(salt, 8); // 8バイト制限が追加
        Packet pac = new PacketA();
        do {
            md.update(password); // PBKDF1では初回のみ
            byte[] h = md.digest(s);
            for ( int cn = 1; cn < c; cn++ ) { // 1回のみ
                h = md.digest(h);
            }
            pac.write(h);
            md.update(h);
        } while ( pac.size() < dkLen );
        byte[] k = new byte[dkLen];
        pac.read(k);
        return k;
    }

    /**
     * PBKDF1と互換の長さ
     * @param password
     * @return 256bit
     */
    @Override
    public byte[] kdf(byte[] password) {
        return kdf(password, 16);
    }
    
}
