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

import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.lang.Bin;
import net.siisise.security.key.EdDSAPrivateKey;
import net.siisise.security.key.EdDSAPublicKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class EdDSATest {
    
    public EdDSATest() {
    }

    /**
     * Test of init25519 method, of class EdDSA.
     */
    @Test
    public void testInit25519() {
        System.out.println("init25519");
        EdDSA instance = new EdDSA();
        instance.init25519();
    }

    /**
     * Test of init448 method, of class EdDSA.
     */
    @Test
    public void testInit448() {
        System.out.println("init448");
        EdDSA instance = new EdDSA();
        instance.init448();
    }

    /**
     * Test of getKeyLength method, of class EdDSA.
     */
    @Test
    public void testGetKeyLength() {
        System.out.println("getKeyLength");
        EdDSA instance = new EdDSA();
        instance.genPrvKey(new EdDSA.EdWards25519());
        int expResult = 256/8;
        int result = instance.getKeyLength();
        assertEquals(expResult, result);
    }

    /**
     * Test of update method, of class EdDSA.
     */
    @Test
    public void testUpdate() {
        System.out.println("update");
        byte[] src = null;
        int offset = 0;
        int length = 0;
        EdDSA instance = new EdDSA();
        instance.init25519();
        instance.update(src, offset, length);
    }

    /**
     * Test of genPrvKey method, of class EdDSA.
     */
    @Test
    public void testGenPrvKey() {
        System.out.println("genPrvKey");
        EdDSA instance = new EdDSA();
        EdDSA.EdWards25519 curve = instance.init25519();
        int expResult = 32;
        byte[] result = instance.genPrvKey(curve);
        OCTETSTRING oct = (OCTETSTRING) ASN1Util.toASN1(result);
        
        assertEquals(expResult, oct.getValue().length);
    }

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testGenPubKey() {
        System.out.println("genPubKey");
        byte[] prvKey = Bin.toByteArray("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(new EdDSA.EdWards25519(), prvKey);
        EdDSA instance = new EdDSA(pkey);
        byte[] expResult = Bin.toByteArray("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        byte[] result = instance.genPubKey();
        System.out.println(Bin.toHex(expResult));
        System.out.println(Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of sign method, of class EdDSA.
     */
    @Test
    public void testSign() {
        System.out.println("sign");
        byte[] prvKey = Bin.toByteArray("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(prvKey);
        EdDSA instance = new EdDSA(pkey);
        byte[] expResult = Bin.toByteArray("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        instance.update(new byte[0]);
        byte[] result = instance.sign();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of verify method, of class EdDSA.
     */
    @Test
    public void testVerify() {
        System.out.println("verify");
        byte[] sign = Bin.toByteArray("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        byte[] pk = Bin.toByteArray("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
        EdDSAPublicKey pubKey = new EdDSAPublicKey(EdDSA.init25519(), pk);
        EdDSA instance = new EdDSA(pubKey);
        instance.update(new byte[0]);
        boolean expResult = true;
        boolean result = instance.verify(sign);
        assertEquals(expResult, result);
    }
    
}
