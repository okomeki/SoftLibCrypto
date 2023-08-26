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
    
}
