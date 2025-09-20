/*
 * Copyright 2025 okome.
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

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.interfaces.RSAPrivateKey;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.io.Output;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;

/**
 * RSASP1 / RSAVP1 っぽいもの
 */
public class RSASP1 extends Output.AbstractOutput implements SignVerify {

    private RSAMiniPrivateKey prv;
    private RSAPublicKey pub;
    private final MessageDigest md;
    private Packet d;

    /**
     * ハッシュなし
     * @param prv 鍵
     */
    public RSASP1(RSAPrivateKey prv) {
        this.prv = PKCS1.toCrt(prv);
        md = null;
        d = new PacketA();
    }

    public RSASP1(java.security.interfaces.RSAPublicKey pub) {
        this.pub = PKCS1.toPub(pub);
        md = null;
        d = new PacketA();
    }

    /**
     * 
     * @param prv RSA私有鍵
     * @param h 事前ハッシュを実施する場合
     */
    public RSASP1(RSAPrivateKey prv, MessageDigest h) {
        this.prv = PKCS1.toCrt(prv);
        md = h;
        d = new PacketA();
    }

    public RSASP1(RSAPublicKey pub, MessageDigest h) {
        this.pub = pub;
        md = h;
        d = new PacketA();
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        if (md != null) {
            md.update(src, offset, length);
        } else {
            d.write(src, offset, length);
        }
    }

    @Override
    public byte[] sign() {
        
        if (md != null) {
            d.write(md.digest());
        }
        byte[] m = d.toByteArray();
        BigInteger n = PKCS1.OS2IP(m);
        int nlen = (prv.getModulus().bitLength() + 7) / 8; // 仮
        return PKCS1.I2OSP(prv.rsasp1(n), nlen);
    }
    
    @Override
    public boolean verify(byte[] sign) {
        if (md != null) {
            d.write(md.digest());
        }
        byte[] m = d.toByteArray();
        BigInteger M = PKCS1.OS2IP(m);
        BigInteger s = PKCS1.OS2IP(sign);
        int nlen = (pub.getModulus().bitLength() + 7) / 8;
        return pub.rsavp1(s).equals(M);
    }

    @Override
    public int getKeyLength() {
        if ( prv != null ) {
            return prv.getModulus().bitLength() / 8;
        }
        if ( pub != null ) {
            return pub.getModulus().bitLength() / 8;
        }
        throw new IllegalStateException();
    }
}
