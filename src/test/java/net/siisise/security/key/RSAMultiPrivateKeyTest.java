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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import net.siisise.iso.asn1.ASN1Object;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.SEQUENCE;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class RSAMultiPrivateKeyTest {

    private SecureRandom srnd;
    
    public RSAMultiPrivateKeyTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() throws NoSuchAlgorithmException {
        srnd = SecureRandom.getInstanceStrong();
    }
    
    @AfterEach
    public void tearDown() {
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
        ASN1Object expResult = instance.rebind(new ASN1Convert());
        SEQUENCE result = instance.getPKCS1ASN1();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
}
