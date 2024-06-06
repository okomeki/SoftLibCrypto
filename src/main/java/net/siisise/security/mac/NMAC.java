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
package net.siisise.security.mac;

import java.security.MessageDigest;

/**
 * RFC 6151
 * HMAC の元のように書かれているNMAC
 * H(key1 H(key2 M))
 */
public class NMAC implements MAC {
    
    MessageDigest md;
    byte[] k1;
    
    public NMAC(MessageDigest md) {
        setMD(md);
    }
    
    public NMAC(MessageDigest md, byte[] key1, byte[] key2) {
        setMD(md);
        init(key1, key2);
    }
    
    private void setMD(MessageDigest md) {
        this.md = md;
    }

    @Override
    public void init(byte[] key) {
        k1 = new byte[key.length - (key.length / 2)];
        System.arraycopy(key, 0, k1, 0, k1.length);
        md.update(key, k1.length, key.length - k1.length);
    }

    public void init(byte[] key1, byte[] key2) {
        k1 = new byte[key1.length];
        System.arraycopy(key1, 0, k1, 0, key1.length);
        md.update(key2);
    }

    @Override
    public int getMacLength() {
        return md.getDigestLength();
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        md.update(src, offset, length);
    }

    @Override
    public byte[] sign() {
        byte[] m = md.digest();
        md.update(k1);
        return md.digest(m);
    }
}
