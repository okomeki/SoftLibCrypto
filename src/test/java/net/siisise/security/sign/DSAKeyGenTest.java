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
package net.siisise.security.sign;

import java.math.BigInteger;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class DSAKeyGenTest {
    
    public DSAKeyGenTest() {
    }

    /**
     * Test of gen method, of class DSAKeyGen.
     */
    @Test
    public void testGen() {
        System.out.println("gen");
        DSAKeyGen.LNPair lp = DSAKeyGen.LN3025;
        DSAKeyGen instance = new DSAKeyGen();
        DSAPrivateKey expResult = null;
//        DSAPrivateKey result = instance.gen(lp);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of genPrivateKey method, of class DSAKeyGen.
     */
    @Test
    public void testGenPrivateKey() {
        System.out.println("genPrivateKey");
        DSAKeyGen instance = new DSAKeyGen();
        DSADomain domain = instance.genDomain(DSAKeyGen.LN3025);
        DSAPrivateKey expResult = null;
        
//        DSAPrivateKey result = instance.genPrivateKey(domain);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of genK method, of class DSAKeyGen.
     */
    @Test
    public void testGenK() {
        System.out.println("genK");
        DSAKeyGen instance = new DSAKeyGen();
        BigInteger expResult = null;
//        BigInteger result = instance.genK();
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of genDomain method, of class DSAKeyGen.
     */
    @Test
    public void testGenDomain() {
        System.out.println("genDomain");
        DSAKeyGen.LNPair ln = DSAKeyGen.LN2022;
        DSAKeyGen instance = new DSAKeyGen();
//        DSADomain expResult = null;
        DSADomain result = instance.genDomain(ln);
        assertNotNull(result);
        assertTrue(result.getP().isProbablePrime(100));
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of toBin method, of class DSAKeyGen.
     */
    @Test
    public void testToBin() {
        System.out.println("toBin");
        BigInteger num = BigInteger.valueOf(0x3fff);
        DSAKeyGen instance = new DSAKeyGen();
        byte[] expResult = {0x3f, (byte)0xff};
        byte[] result = instance.toBin(num);
        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of toNum method, of class DSAKeyGen.
     */
    @Test
    public void testToNum() {
        System.out.println("toNum");
        byte[] bin = { (byte)0x90, 0x3e };
        DSAKeyGen instance = new DSAKeyGen();
        BigInteger expResult = BigInteger.valueOf( 0x903e);
        BigInteger result = instance.toNum(bin);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of a22valid method, of class DSAKeyGen.
     */
    @Test
    public void testA22valid() {
        System.out.println("a22valid");
        DSAKeyGen instance = new DSAKeyGen();
        DSADomain d = instance.genDomain(DSAKeyGen.LN3025);
        boolean result = instance.a22valid(d);
        assertTrue(result);
    }

    /**
     * Test of testC3 method, of class DSAKeyGen.
     */
    @Test
    public void testTestC3() {
        System.out.println("testC3");
        BigInteger n = BigInteger.valueOf(17);
        DSAKeyGen instance = new DSAKeyGen();
        boolean expResult = true;
        boolean result = instance.testC3(n);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
    
}
