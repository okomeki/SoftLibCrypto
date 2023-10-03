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
package net.siisise.security.mac;

import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class XCBCTest {
    
    public XCBCTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    @BeforeEach
    public void setUp() {
    }
    
    @AfterEach
    public void tearDown() {
    }

    /**
     * RFC 3566 Tesc Case #1
     */
    @Test
    public void testCase1() {
        System.out.println("XCBC Test Case #1");
        byte[] key = Bin.toByteArray("000102030405060708090a0b0c0d0e0f");
        byte[] example = Bin.toByteArray("75f0251d528ac01c4573dfd584d79f29");
        XCBC instance = new XCBC(new AES());
        instance.init(key);
        byte[] result = instance.sign();
        assertArrayEquals(example, result);
    }

    /**
     * RFC 3566 Tesc Case #2
     */
    @Test
    public void testCase2() {
        System.out.println("XCBC Test Case #2");
        byte[] key = Bin.toByteArray("000102030405060708090a0b0c0d0e0f");
        byte[] m = Bin.toByteArray("000102");
        byte[] example = Bin.toByteArray("5b376580ae2f19afe7219ceef172756f");
        XCBC instance = new XCBC(new AES());
        instance.init(key);
        instance.update(m);
        byte[] result = instance.sign();
        assertArrayEquals(example, result);
    }

    /**
     * RFC 3566 Tesc Case #3
     */
    @Test
    public void testCase3() {
        System.out.println("XCBC Test Case #3");
        byte[] key = Bin.toByteArray("000102030405060708090a0b0c0d0e0f");
        byte[] example = Bin.toByteArray("d2a246fa349b68a79998a4394ff7a263");
        XCBC instance = new XCBC(new AES());
        instance.init(key);
        instance.update(key);
        byte[] result = instance.sign();
        assertArrayEquals(example, result);
    }

    /**
     * RFC 3566 Tesc Case #4
     */
    @Test
    public void testCase4() {
        System.out.println("XCBC Test Case #4");
        byte[] key = Bin.toByteArray("000102030405060708090a0b0c0d0e0f");
        byte[] m = Bin.toByteArray("000102030405060708090a0b0c0d0e0f10111213");
        byte[] example = Bin.toByteArray("47f51b4564966215b8985c63055ed308");
        XCBC instance = new XCBC(new AES());
        instance.init(key);
        instance.update(m);
        byte[] result = instance.sign();
        assertArrayEquals(example, result);
    }

    /**
     * RFC 3566 Tesc Case #5
     */
    @Test
    public void testCase5() {
        System.out.println("XCBC Test Case #5");
        byte[] key = Bin.toByteArray("000102030405060708090a0b0c0d0e0f");
        byte[] m = Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        byte[] example = Bin.toByteArray("f54f0ec8d2b9f3d36807734bd5283fd4");
        XCBC instance = new XCBC(new AES());
        instance.init(key);
        instance.update(m);
//        byte[] result = instance.sign();
//        assertArrayEquals(example, result);
        assertTrue(instance.verify(example));
    }

    /**
     * RFC 3566 Tesc Case #6
     */
    @Test
    public void testCase6() {
        System.out.println("XCBC Test Case #6");
        byte[] key = Bin.toByteArray("000102030405060708090a0b0c0d0e0f");
        byte[] m = Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f2021");
        byte[] example = Bin.toByteArray("becbb3bccdb518a30677d5481fb6b4d8");
        XCBC instance = new XCBC(new AES());
        instance.init(key);
        instance.update(m);
//        byte[] result = instance.sign();
//        assertArrayEquals(example, result);
        assertTrue(instance.verify(example));
    }

    /**
     * RFC 3566 Tesc Case #7
     */
    @Test
    public void testCase7() {
        System.out.println("XCBC Test Case #7");
        byte[] key = Bin.toByteArray("000102030405060708090a0b0c0d0e0f");
        byte[] m = new byte[1000];
        byte[] example = Bin.toByteArray("f0dafee895db30253761103b5d84528f");
        XCBC instance = new XCBC(new AES());
        instance.init(key);
        instance.update(m);
        assertTrue(instance.verify(example));
    }

    /**
     * Test of sign method, of class XCBC.
     */
/*
    @Test
    public void testSign() {
        System.out.println("sign");
        XCBC instance = new XCBC(new AES());
        byte[] expResult = null;
        byte[] result = instance.sign();
        assertArrayEquals(expResult, result);
    }
*/
    /**
     * Test of getMacLength method, of class XCBC.
     */
    @Test
    public void testGetMacLength() {
        System.out.println("getMacLength");
        XCBC instance = new XCBC(new AES());
        int expResult = 16;
        int result = instance.getMacLength();
        assertEquals(expResult, result);
    }
    
}
