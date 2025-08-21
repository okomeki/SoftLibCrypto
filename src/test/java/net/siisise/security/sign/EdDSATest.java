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

    static byte[] KEY1 = Bin.toByteArray("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    static byte[] PUB1 = Bin.toByteArray("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    static byte[] SIG1 = Bin.toByteArray("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
    static byte[] KEY2 = Bin.toByteArray("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    static byte[] PUB2 = Bin.toByteArray("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    static byte[] MSG2 = Bin.toByteArray("72");
    static byte[] SIG2 = Bin.toByteArray("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

    static byte[] KEY4481 = Bin.toByteArray("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    static byte[] PUB4481 = Bin.toByteArray("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
    static byte[] SIG4481 = Bin.toByteArray("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");

    static byte[] KEY4482 = Bin.toByteArray("c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");
    static byte[] PUB4482 = Bin.toByteArray("43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");
    static byte[] MSG4482 = Bin.toByteArray("03");
    static byte[] SIG4482 = Bin.toByteArray("26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00");
    

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testGenPubKey255191() {
        System.out.println("genPubKey25519 1");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(new EdDSA.EdWards25519(), KEY1);
        EdDSA instance = new EdDSA(pkey);
        byte[] expResult = PUB1;
        byte[] result = instance.genPubKey();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testGenPubKey255192() {
        System.out.println("genPubKey25519 2");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(new EdDSA.EdWards25519(), KEY2);
        EdDSA instance = new EdDSA(pkey);
        byte[] expResult = PUB2;
        byte[] result = instance.genPubKey();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testGenPubKey4481() {
        System.out.println("genPubKey448 1");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(new EdDSA.EdWards448(), KEY4481);
        EdDSA instance = new EdDSA(pkey);
        byte[] result = instance.genPubKey();
        System.out.println("s:" + pkey.gets().toString(16));
        assertArrayEquals(PUB4481, result);
    }

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testGenPubKey4482() {
        System.out.println("genPubKey448 2");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(new EdDSA.EdWards448(), KEY4482);
        EdDSA instance = new EdDSA(pkey);
        byte[] expResult = PUB4482;
        byte[] result = instance.genPubKey();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of sign method, of class EdDSA.
     */
    @Test
    public void testSign255191() {
        System.out.println("sign1");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(new EdDSA.EdWards25519(), KEY1);
        EdDSA instance = new EdDSA(pkey);
        byte[] expResult = SIG1;
        instance.update(new byte[0]);
        byte[] result = instance.sign();
        System.out.println(" A:"+Bin.toHex(pkey.getA()));
        System.out.println("Ex:"+Bin.toHex(expResult));
        System.out.println("Rs:"+Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of sign method, of class EdDSA.
     */
    @Test
    public void testSign4481() {
        System.out.println("sign448 1");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(new EdDSA.EdWards448(),KEY4481);
        EdDSA instance = new EdDSA(pkey);
        byte[] expResult = SIG4481;
        instance.update(new byte[0]);
        byte[] result = instance.sign();
        EdDSAPublicKey pub = pkey.getPublicKey();
        System.out.println("Ex:"+Bin.toHex(expResult));
        System.out.println("Rs:"+Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of sign method, of class EdDSA.
     */
    @Test
    public void testSign255192() {
        System.out.println("sign25519 2");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(KEY2);
        EdDSA instance = new EdDSA(pkey);
        byte[] expResult = SIG2;
        instance.update(MSG2);
        byte[] result = instance.sign();
        System.out.println("Ex:"+Bin.toHex(expResult));
        System.out.println("Rs:"+Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of sign method, of class EdDSA.
     */
    @Test
    public void testSign4482() {
        System.out.println("sign448 2");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(new EdDSA.EdWards448(),KEY4482);
        EdDSA instance = new EdDSA(pkey);
        byte[] expResult = SIG4482;
        instance.update(MSG4482);
        byte[] result = instance.sign();
        EdDSAPublicKey pub = pkey.getPublicKey();
        System.out.println("Ex:"+Bin.toHex(expResult));
        System.out.println("Rs:"+Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of verify method, of class EdDSA.
     */
    @Test
    public void testVerify255191() {
        System.out.println("verify25519 1");
        byte[] sign = SIG1;
        byte[] pk = PUB1;
        EdDSAPublicKey pubKey = new EdDSAPublicKey(EdDSA.init25519(), pk);
        EdDSA instance = new EdDSA(pubKey);
        instance.update(new byte[0]);
        boolean expResult = true;
        boolean result = instance.verify(sign);
        assertEquals(expResult, result);
    }

    /**
     * Test of verify method, of class EdDSA.
     */
    @Test
    public void testVerify4481() {
        System.out.println("verify448 1");
        byte[] sign = SIG4481;
        byte[] pk = PUB4481;
        EdDSAPublicKey pubKey = new EdDSAPublicKey(EdDSA.init448(), pk);
        EdDSA instance = new EdDSA(pubKey);
        instance.update(new byte[0]);
        boolean expResult = true;
        boolean result = instance.verify(sign);
        assertEquals(expResult, result);
    }

    /**
     * Test of verify method, of class EdDSA.
     */
    @Test
    public void testVerify2() {
        System.out.println("verify2");
        byte[] sign = SIG2;
        byte[] pk = PUB2;
        EdDSAPublicKey pubKey = new EdDSAPublicKey(EdDSA.init25519(), pk);
        EdDSA instance = new EdDSA(pubKey);
        instance.update(MSG2);
        boolean expResult = true;
        boolean result = instance.verify(sign);
        assertEquals(expResult, result);
    }
    
    /**
     * Test of verify method, of class EdDSA.
     */
    @Test
    public void testVerify4482() {
        System.out.println("verify448 2");
        byte[] sign = SIG4482;
        byte[] pk = PUB4482;
        EdDSAPublicKey pubKey = new EdDSAPublicKey(new EdDSA.EdWards448(), pk);
        EdDSA instance = new EdDSA(pubKey);
        instance.update(MSG4482);
        boolean expResult = true;
        boolean result = instance.verify(sign);
        assertEquals(expResult, result);
    }
}
