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
package net.siisise.security.key;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.transform.TransformerException;
import net.siisise.bind.Rebind;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEList;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class RSAPublicKeyTest {
    
    public RSAPublicKeyTest() {
    }

    /**
     * Test of getPublicExponent method, of class RSAPublicKey.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testGetPublicExponent() throws NoSuchAlgorithmException {
        System.out.println("getPublicExponent");
        RSAPublicKey instance = RSAKeyGen.generatePrivateKey(2048).getPublicKey();
        BigInteger expResult = null;
        BigInteger result = instance.getPublicExponent();
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of getModulus method, of class RSAPublicKey.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testGetModulus() throws NoSuchAlgorithmException {
        System.out.println("getModulus");
        RSAPublicKey instance = RSAKeyGen.generatePrivateKey(2048).getPublicKey();
        BigInteger expResult = null;
        BigInteger result = instance.getModulus();
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of getAlgorithm method, of class RSAPublicKey.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testGetAlgorithm() throws NoSuchAlgorithmException {
        System.out.println("getAlgorithm");
        RSAPublicKey instance = RSAKeyGen.generatePrivateKey(2048).getPublicKey();
        String expResult = "RSA";
        String result = instance.getAlgorithm();
        assertEquals(expResult, result);
    }

    /**
     * Test of getFormat method, of class RSAPublicKey.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testGetFormat() throws NoSuchAlgorithmException {
        System.out.println("getFormat");
        RSAPublicKey instance = RSAKeyGen.generatePrivateKey(2048).getPublicKey();
        String expResult = "X.509";
        String result = instance.getFormat();
        assertEquals(expResult, result);
    }

    /**
     * Test of getEncoded method, of class RSAPublicKey.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testGetEncoded() throws NoSuchAlgorithmException {
        System.out.println("getEncoded");
        RSAPublicKey instance = RSAKeyGen.generatePrivateKey(2048).getPublicKey();
        byte[] expResult = null;
        byte[] result = instance.getEncoded();
//        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of rsaep method, of class RSAPublicKey.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testRsaep() throws NoSuchAlgorithmException {
        System.out.println("rsaep");
        BigInteger m = BigInteger.valueOf(7);
        RSAPublicKey instance = RSAKeyGen.generatePrivateKey(2048).getPublicKey();
        BigInteger expResult = null;
        BigInteger result = instance.rsaep(m);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of rsavp1 method, of class RSAPublicKey.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testRsavp1() throws NoSuchAlgorithmException {
        System.out.println("rsavp1");
        BigInteger s = BigInteger.valueOf(7);
        RSAPublicKey instance = RSAKeyGen.generatePrivateKey(2048).getPublicKey();
        BigInteger expResult = null;
        BigInteger result = instance.rsavp1(s);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
    
    @Test
    public void testFormat() throws NoSuchAlgorithmException {
        System.out.println("format");
        RSAPublicKey instance = RSAKeyGen.generatePrivateKey(2048).getPublicKey();
       // String format = instance.getFormat();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
        KeyPair pair = gen.genKeyPair();
        PrivateKey prv = pair.getPrivate();
        System.out.println(" algorithm: " + prv.getAlgorithm());
        System.out.println(" format: " + prv.getFormat());
        System.out.println(" string: " + prv.toString());
        PublicKey pub = pair.getPublic();
  //      System.out.println("algorithm: " + pub.getAlgorithm());
        System.out.println("format: " + pub.getFormat());
        assertEquals(pub.getFormat(), instance.getFormat());
    }
    
    @Test
    public void testRebind() throws NoSuchAlgorithmException {
        System.out.println("rebind");
        BigInteger n = BigInteger.valueOf(1234567890123456l);
        BigInteger e = BigInteger.valueOf(65537);
        RSAPublicKey instance = new RSAPublicKey(n,e);
        SEQUENCE ex1ASN1 = new SEQUENCEList();
        ex1ASN1.add(instance.getModulus());
        ex1ASN1.add(instance.getPublicExponent());
        ASN1Convert asncnv = new ASN1Convert();
//        ASN1Object asn1 = instance.rebind(asncnv);
        byte[] pubASN1 = instance.getPKCS1Encoded();
//        byte[] rebindASN1 = instance.rebind(asncnv).encodeAll();
        byte[] rebind2ASN1 = Rebind.valueOf(instance, asncnv).encodeAll();
        try {
            ASN1Tag ex1 = ASN1Util.toASN1(rebind2ASN1);
            
            System.out.println(ASN1Util.toString(ASN1Util.toXML(ex1)));
        } catch (TransformerException ex) {
            Logger.getLogger(RSAPublicKeyTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        byte[] exASN1 = {0x30,0x0e,0x02,0x07,0x04,0x62,-43,60,-118,-70,-64,0x02,0x03,0x01,0,0x01};
        assertArrayEquals(pubASN1, ex1ASN1.encodeAll());
//        assertArrayEquals(pubASN1, rebindASN1);
        assertArrayEquals(pubASN1, rebind2ASN1);
        assertArrayEquals(pubASN1, exASN1);
    }
    
}
