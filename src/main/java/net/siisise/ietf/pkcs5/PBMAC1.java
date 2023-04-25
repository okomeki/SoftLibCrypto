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
public class PBMAC1 {
    static final OBJECTIDENTIFIER id_PBMAC1 = PBKDF2.PKCS5.sub(14);

    private final PBKDF2 kdf;
//    private MAC mac;
    
    /**
     * 
     * @param kdf MD 設定済みのPBKDF2
     */
    public PBMAC1(PBKDF2 kdf) {
        this.kdf = kdf;
    }
    
    public void init(MAC mac) {
        kdf.init(mac);
        int dkLen = mac.getMacLength();
//        this.mac = mac;
    }

    /**
     * PBMAC1の本体.
     * たぶんこんなかんじ? 
     * @param src メッセージ M
     * @param mac HMAC-XXXX
     * @param password パスワード P
     * @param salt ソルト S
     * @param c 繰り返し最小1000ぐらいから
     * @return メッセージ認証コード T
     */
    public byte[] mac(byte[] src, MAC mac, byte[] password, byte[] salt, int c) {
        int dkLen = mac.getMacLength(); // 長さ(オクテット)
        byte[] dk = kdf.pbkdf(password, salt, c, dkLen);
        mac.init(dk);
        return mac.doFinal(src);
    }
}
