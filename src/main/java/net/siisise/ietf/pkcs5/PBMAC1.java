/*
 * Copyright 2022 okome.
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

import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.mac.MAC;

/**
 * PKCS #5
 * RFC 8018 7.1. PBMAC1
 */
public class PBMAC1 implements MAC {
    public static final OBJECTIDENTIFIER id_PBMAC1 = PBKDF2.PKCS5.sub(14);

    private final PBKDF2 kdf;
    private MAC mac;
    /**
     * 7.1.1. 1. salt S
     */
    byte[] salt;
    /**
     * 7.1.1. 反復回数 iteration count
     */
    int c;
    
    /**
     * 
     * @param kdf MD 設定済みのPBKDF2
     * @param kdfMac PBKDF2用PRF MAC 省略時 HMAC-SHA1
     * @param mac 本体MAC
     */
    public PBMAC1(PBKDF2 kdf, MAC kdfMac, MAC mac) {
        this.kdf = kdf;
        if ( kdfMac != null ) {
            kdf.init(kdfMac);
        }
        this.mac = mac;
    }
    
    public PBMAC1(MAC mac) {
        this(new PBKDF2(), null, mac);
    }
    
    /**
     * 7.1.1. PBMAC1 生成
     * @param password パスワード
     * @param salt 7.1.1. ソルト S
     * @param c 反復回数 最小1000ぐらいから
     */
    public void init(byte[] password, byte[] salt, int c) {
        this.salt = salt;
        this.c = c;
        if (mac != null) {
            kdf.init(mac);
        }
        int dkLen = mac.getMacLength();
        // 3.
        byte[] dk = kdf.pbkdf(password, salt, c, dkLen);
        mac.init(dk);
    }

    @Override
    public void init(byte[] password) {
        if (mac != null) {
            kdf.init(mac);
        }
        int dkLen = mac.getMacLength();
        // 3.
        byte[] dk = kdf.pbkdf(password, salt, c, dkLen);
        mac.init(dk);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        mac.update(src, offset, length);
    }

    @Override
    public byte[] sign() {
        return mac.sign();
    }

    @Override
    public int getMacLength() {
        return mac.getMacLength();
    }
}
