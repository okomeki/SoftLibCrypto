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

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.xml.transform.TransformerException;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.SEQUENCE;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class RSAMultiPrivateKeyTest {

    private SecureRandom srnd;
    int keylen = 1024 * 3;
    
    public RSAMultiPrivateKeyTest() {
    }
    
    @BeforeEach
    public void setUp() throws NoSuchAlgorithmException {
        srnd = SecureRandom.getInstanceStrong();
    }
    
    @AfterEach
    public void tearDown() {
    }

    /**
     * Test of rsadp method, of class RSAPrivateCrtKey.
     */
    @Test
    public void testRsadp() {
        System.out.println("rsadp");
        BigInteger m = BigInteger.probablePrime(1500, srnd);
        RSAPrivateCrtKey instance = RSAKeyGen.generatePrivateKey(keylen, srnd, 4);
        RSAPublicKey pub = instance.getPublicKey();
        BigInteger c = pub.rsaep(m);
        BigInteger result = instance.rsadp(c);
        assertEquals(m, result);
    }

    /**
     * Test of rsasp1 method, of class RSAPrivateCrtKey.
     */
    @Test
    public void testRsasp1() {
        System.out.println("rsasp1");
        BigInteger m = BigInteger.probablePrime(1500, srnd);
        RSAPrivateCrtKey instance = RSAKeyGen.generatePrivateKey(keylen, srnd, 2);
        RSAPublicKey pub = instance.getPublicKey();
        BigInteger result = instance.rsasp1(m);
        
        assertEquals(m, pub.rsavp1(result));
    }

    /**
     * Test of getPrivateKey method, of class RSAPrivateCrtKey.
     */
    @Test
    public void testGetPrivateKey() {
        System.out.println("getPrivateKey");
        RSAPrivateCrtKey instance = RSAKeyGen.generatePrivateKey(keylen, srnd, 2);
        RSAMiniPrivateKey result = instance.getPrivateKey();
        assertEquals(instance.getModulus(), result.getModulus());
        assertEquals(instance.getPrivateExponent(), result.getPrivateExponent());
    }

    /**
     * Test of getPublicKey method, of class RSAPrivateCrtKey.
     */
    @Test
    public void testGetPublicKey() {
        System.out.println("getPublicKey");
        RSAPrivateCrtKey instance = RSAKeyGen.generatePrivateKey(keylen, srnd, 2);
        RSAPublicKey result = instance.getPublicKey();
        
        assertEquals(instance.publicExponent, result.getPublicExponent());
        assertEquals(instance.getModulus(), result.getModulus());
    }

    /**
     * Test of modPow method, of class RSAMultiPrivateKey.
     */
/*
    @Test
    public void testModPow() {
        System.out.println("modPow");
        BigInteger s = null;
        RSAMultiPrivateKey instance = null;
        BigInteger expResult = null;
        BigInteger result = instance.modPow(s);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
*/

    /**
     * Test of getPKCS1ASN1 method, of class RSAMultiPrivateKey.
     * rebind と ASN.1 が一致するだけの確認.
     */
    @Test
    public void testGetPKCS1ASN1Rebind() {
        System.out.println("getPKCS1ASN1 rebind");
        RSAMultiPrivateKey instance = (RSAMultiPrivateKey) RSAKeyGen.generatePrivateKey(256, srnd, 4);
        ASN1Tag expResult = instance.rebind(new ASN1Convert());
        SEQUENCE result = instance.getPrivateASN1();
        try {
            System.out.println(ASN1Util.toString(ASN1Util.toXML(result)));
            System.out.println(ASN1Util.toString(ASN1Util.toXML(expResult)));
        } catch (TransformerException ex) {
            Logger.getLogger(RSAMultiPrivateKeyTest.class.getName()).log(Level.SEVERE, null, ex);
        }
        assertTrue(expResult.equals( result));
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of getFormat method, of class RSAPrivateCrtKey.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testGetFormat() throws NoSuchAlgorithmException {
        System.out.println("getFormat");
        RSAPrivateCrtKey instance = RSAKeyGen.generatePrivateKey(keylen, srnd, 2);
        String expResult = "PKCS#8";
        String result = instance.getFormat();
        assertEquals(expResult, result);
    }

    /**
     * Test of getEncoded method, of class RSAPrivateCrtKey.
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.io.IOException
     */
    @Test
    public void testGetEncoded() throws NoSuchAlgorithmException, IOException {
        System.out.println("getEncoded");
        RSAPrivateCrtKey instance = RSAKeyGen.generatePrivateKey(keylen, srnd, 2);
//        KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
//        KeyPair pair = gen.genKeyPair();
//        PrivateKey examplePrivateKey = pair.getPrivate();
//        byte[] k = examplePrivateKey.getEncoded();
//        FileIO.dump(k);
//        ASN1Object asn = ASN1Util.toASN1(k);
//        System.out.println(asn);
        byte[] result = instance.getEncoded();
        System.out.println(ASN1Util.DERtoASN1(result));
        System.out.println(ASN1Util.toASN1(result));
//        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of toString method, of class RSAPrivateCrtKey.
     */
    @Test
    public void testToString() {
        System.out.println("toString");
        RSAPrivateCrtKey instance = RSAKeyGen.generatePrivateKey(keylen, srnd, 2);
        String expResult = "Siisise RSA private CRT key, " + keylen + " bits";
        String result = instance.toString();
        assertEquals(expResult, result);
    }

    @Test
    public void testCreatePrivateKey() throws Exception {
        System.out.println("createPrivateKey");
        int len = 2049;
        RSAPrivateCrtKey key = RSAKeyGen.generatePrivateKey(len);
//        assertEquals(expResult, key);
        // TODO review the generated test code and remove the default call to fail.
        BigInteger p1e = key.prime1.subtract(BigInteger.ONE);
        BigInteger p2e = key.prime2.subtract(BigInteger.ONE);
//        assertEquals(key.publicExponent.modInverse(key.modulus), );
        assertEquals(key.modulus, key.prime1.multiply(key.prime2));
        assertEquals(key.exponent1, key.publicExponent.modInverse(p1e));
        assertEquals(key.exponent2, key.publicExponent.modInverse(p2e));
        assertEquals(key.exponent1, key.privateExponent.mod(p1e));
        assertEquals(key.exponent2, key.privateExponent.mod(p2e));
        assertEquals(key.publicExponent, key.privateExponent.modInverse(RSAKeyGen.lcm(p1e,p2e)));
        assertEquals(key.coefficient, key.prime2.modInverse(key.prime1));
//        assertEquals(key.privateExponent, key.exponent1.multiply(key.exponent2).mod(RSA.lcm(p1e, p2e)));
    }
}
