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
package net.siisise.security.digest;

import net.siisise.lang.Bin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/ParallelHash_samples.pdf
 */
public class ParallelHashTest {
    
    public ParallelHashTest() {
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
     * Test of ParallelHash Sample #1.
     */
    @Test
    public void testSample1() {
        System.out.println("testParallelHash128 Sample #1");
        ParallelHash instance = new ParallelHash128(8,256,null);
        byte[] src = Bin.toByteArray("000102030405060710111213141516172021222324252627");
        byte[] expResult = Bin.toByteArray("ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of ParallelHash Sample #2.
     */
    @Test
    public void testSample2() {
        System.out.println("testParallelHash128 Sample #2");
        int B = 8;
        String S = "Parallel Data";
        ParallelHash instance = new ParallelHash128(B,256,S);
        byte[] src = Bin.toByteArray("000102030405060710111213141516172021222324252627");
        byte[] expResult = Bin.toByteArray("fc484dcb3f84dceedc353438151bee58157d6efed0445a81f165e495795b7206");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of ParallelHash Sample #2.
     */
    @Test
    public void testSample3() {
        System.out.println("testParallelHash128 Sample #3");
        int B = 12;
        String S = "Parallel Data";
        ParallelHash instance = new ParallelHash128(B,256,S);
        byte[] src = Bin.toByteArray("000102030405060708090A0B10111213"
                + "1415161718191A1B2021222324252627"
                + "28292A2B303132333435363738393A3B"
                + "404142434445464748494A4B50515253"
                + "5455565758595A5B");
        byte[] expResult = Bin.toByteArray("f7fd5312896c6685c828af7e2adb97e393e7f8d54e3c2ea4b95e5aca3796e8fc");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }


    /**
     * Test of ParallelHash Sample #1.
     */
    @Test
    public void testSample1_256() {
        System.out.println("testParallelHash256 Sample #1");
        int B = 8;
        ParallelHash instance = new ParallelHash256(B,512,null);
        byte[] src = Bin.toByteArray("000102030405060710111213141516172021222324252627");
        byte[] expResult = Bin.toByteArray("bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c45110553"
                + "1b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of ParallelHash Sample #2.
     */
    @Test
    public void testSample2_256() {
        System.out.println("testParallelHash256 Sample #2");
        int B = 8;
        String S = "Parallel Data";
        ParallelHash instance = new ParallelHash256(B,512,S);
        byte[] src = Bin.toByteArray("000102030405060710111213141516172021222324252627");
        byte[] expResult = Bin.toByteArray("cdf15289b54f6212b4bc270528b49526006dd9b54e2b6add1ef6900dda3963bb"
                + "33a72491f236969ca8afaea29c682d47a393c065b38e29fae651a2091c833110");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of ParallelHash Sample #2.
     */
    @Test
    public void testSample3_256() {
        System.out.println("testParallelHash256 Sample #3");
        int B = 12;
        String S = "Parallel Data";
        ParallelHash instance = new ParallelHash256(B,512,S);
        byte[] src = Bin.toByteArray("000102030405060708090A0B10111213"
                + "1415161718191A1B2021222324252627"
                + "28292A2B303132333435363738393A3B"
                + "404142434445464748494A4B50515253"
                + "5455565758595A5B");
        byte[] expResult = Bin.toByteArray("69d0fcb764ea055dd09334bc6021cb7e4b61348dff375da262671cdec3effa8d"
                + "1b4568a6cce16b1cad946ddde27f6ce2b8dee4cd1b24851ebf00eb90d43813e9");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }
}
