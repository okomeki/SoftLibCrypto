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
 * ParallelHashXOF
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/ParallelHashXOF_samples.pdf
 */
public class ParallelHashXOFTest {
    
    public ParallelHashXOFTest() {
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
        System.out.println("testParallelHashXOF128 Sample #1");
        ParallelHash instance = new ParallelHashXOF128(8,256,null);
        byte[] src = Bin.toByteArray("000102030405060710111213141516172021222324252627");
        byte[] expResult = Bin.toByteArray("fe47d661e49ffe5b7d999922c062356750caf552985b8e8ce6667f2727c3c8d3");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of ParallelHash Sample #2.
     */
    @Test
    public void testSample2() {
        System.out.println("testParallelHashXOF128 Sample #2");
        int B = 8;
        String S = "Parallel Data";
        ParallelHash instance = new ParallelHashXOF128(B,256,S);
        byte[] src = Bin.toByteArray("000102030405060710111213141516172021222324252627");
        byte[] expResult = Bin.toByteArray("ea2a793140820f7a128b8eb70a9439f93257c6e6e79b4a540d291d6dae7098d7");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of ParallelHash Sample #2.
     */
    @Test
    public void testSample3() {
        System.out.println("testParallelHashXOF128 Sample #3");
        int B = 12;
        String S = "Parallel Data";
        ParallelHash instance = new ParallelHashXOF128(B,256,S);
        byte[] src = Bin.toByteArray("000102030405060708090A0B10111213"
                + "1415161718191A1B2021222324252627"
                + "28292A2B303132333435363738393A3B"
                + "404142434445464748494A4B50515253"
                + "5455565758595A5B");
        byte[] expResult = Bin.toByteArray("0127ad9772ab904691987fcc4a24888f341fa0db2145e872d4efd255376602f0");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }


    /**
     * Test of ParallelHash Sample #1.
     */
    @Test
    public void testSample1_256() {
        System.out.println("testParallelHashXOF256 Sample #1");
        int B = 8;
        ParallelHash instance = new ParallelHashXOF256(B,512,null);
        byte[] src = Bin.toByteArray("000102030405060710111213141516172021222324252627");
        byte[] expResult = Bin.toByteArray("c10a052722614684144d28474850b410757e3cba87651ba167a5cbddff7f466675fbf84bcae7378ac444be681d729499afca667fb879348bfdda427863c82f1c"
                + "");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of ParallelHash Sample #2.
     */
    @Test
    public void testSample2_256() {
        System.out.println("testParallelHashXOF256 Sample #2");
        int B = 8;
        String S = "Parallel Data";
        ParallelHash instance = new ParallelHashXOF256(B,512,S);
        byte[] src = Bin.toByteArray("000102030405060710111213141516172021222324252627");
        byte[] expResult = Bin.toByteArray("538e105f1a22f44ed2f5cc1674fbd40be803d9c99bf5f8d90a2c8193f3fe6ea7"
                + "68e5c1a20987e2c9c65febed03887a51d35624ed12377594b5585541dc377efc");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of ParallelHash Sample #2.
     */
    @Test
    public void testSample3_256() {
        System.out.println("testParallelHashXOF256 Sample #3");
        int B = 12;
        String S = "Parallel Data";
        ParallelHash instance = new ParallelHashXOF256(B,512,S);
        byte[] src = Bin.toByteArray("000102030405060708090A0B10111213"
                + "1415161718191A1B2021222324252627"
                + "28292A2B303132333435363738393A3B"
                + "404142434445464748494A4B50515253"
                + "5455565758595A5B");
        byte[] expResult = Bin.toByteArray("6b3e790b330c889a204c2fbc728d809f19367328d852f4002dc829f73afd6bce"
                + "fb7fe5b607b13a801c0be5c1170bdb794e339458fdb0e62a6af3d42558970249");
        instance.update(src);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }
}
