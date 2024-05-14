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
 * TupleHash.
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TupleHash_samples.pdf
 */
public class TupleHashTest {

    public TupleHashTest() {
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
     * Test of class TupleHash.
     */
    @Test
    public void testSample128_1() {
        System.out.println("TupleHash128: Sample#1");
        TupleHash instance = new TupleHash128(256, null);
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        byte[] expResult = Bin.toByteArray("c5d8786c1afb9b82111ab34b65b2c0048fa64e6d48e263264ce1707d3ffc8ed1");
        instance.update(tuple1);
        instance.update(tuple2);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of class TupleHash.
     */
    @Test
    public void testSample128_2() {
        System.out.println("TupleHash128: Sample#2");
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        String S = "My Tuple App";
        TupleHash instance = new TupleHash128(256, S);
        byte[] expResult = Bin.toByteArray("75cdb20ff4db1154e841d758e24160c54bae86eb8c13e7f5f40eb35588e96dfb");
        instance.update(tuple1);
        instance.update(tuple2);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of class TupleHash.
     */
    @Test
    public void testSample128_3() {
        System.out.println("TupleHash128: Sample#3");
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        byte[] tuple3 = Bin.toByteArray("202122232425262728");
        String S = "My Tuple App";
        TupleHash instance = new TupleHash128(256, S);
        byte[] expResult = Bin.toByteArray("e60f202c89a2631eda8d4c588ca5fd07f39e5151998deccf973adb3804bb6e84");
        instance.update(tuple1);
        instance.update(tuple2);
        instance.update(tuple3);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }


    /**
     * Test of class TupleHash.
     */
    @Test
    public void testSample256_1() {
        System.out.println("TupleHash256: Sample#4");
        TupleHash instance = new TupleHash256(512, null);
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        byte[] expResult = Bin.toByteArray("cfb7058caca5e668f81a12a20a2195ce97a925f1dba3e7449a56f82201ec6073"
                + "11ac2696b1ab5ea2352df1423bde7bd4bb78c9aed1a853c78672f9eb23bbe194");
        instance.update(tuple1);
        instance.update(tuple2);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of class TupleHash.
     */
    @Test
    public void testSample256_2() {
        System.out.println("TupleHash256: Sample#5");
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        String S = "My Tuple App";
        TupleHash instance = new TupleHash256(512, S);
        byte[] expResult = Bin.toByteArray("147c2191d5ed7efd98dbd96d7ab5a11692576f5fe2a5065f3e33de6bba9f3aa1"
                + "c4e9a068a289c61c95aab30aee1e410b0b607de3620e24a4e3bf9852a1d4367e");
        instance.update(tuple1);
        instance.update(tuple2);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of class TupleHash.
     */
    @Test
    public void testSample256_3() {
        System.out.println("TupleHash256: Sample#6");
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        byte[] tuple3 = Bin.toByteArray("202122232425262728");
        String S = "My Tuple App";
        TupleHash instance = new TupleHash256(512, S);
        byte[] expResult = Bin.toByteArray("45000be63f9b6bfd89f54717670f69a9bc763591a4f05c50d68891a744bcc6e7"
                + "d6d5b5e82c018da999ed35b0bb49c9678e526abd8e85c13ed254021db9e790ce");
        instance.update(tuple1);
        instance.update(tuple2);
        instance.update(tuple3);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }
}
