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
package net.siisise.security.key;

import java.math.BigInteger;
import java.security.MessageDigest;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.security.block.RSA;

/**
 * ISO-18033-2
 */
public class KDF3 implements KDF {

    private MessageDigest md;
    private int pamt;
    private int dkLen;
    
    public KDF3(MessageDigest md) {
        this.md = md;
    }
    
    public void init(int pamt, int len) {
        this.pamt = pamt;
        dkLen = len;
    }

    @Override
    public byte[] kdf(byte[] password, int dkLen) {
        long i = 0;
        Packet pac = new PacketA();
        do {
            md.update(RSA.i2osp(BigInteger.valueOf(i++),pamt));
            pac.write(md.digest(password));
        } while ( pac.size() < dkLen );
        byte[] key = new byte[dkLen];
        pac.read(key);
        return key;
    }

    @Override
    public byte[] kdf(byte[] password) {
        return kdf(password, dkLen);
    }
}
