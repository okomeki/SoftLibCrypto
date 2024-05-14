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
 * TupleHashXOF.
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/TupleHashXOF_samples.pdf
 */
public class TupleHashXOFTest {

    public TupleHashXOFTest() {
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
        System.out.println("TupleHashXOF128: Sample#1");
        TupleHash instance = new TupleHashXOF128(256, null);
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        byte[] expResult = Bin.toByteArray("2f103cd7c32320353495c68de1a8129245c6325f6f2a3d608d92179c96e68488");
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
        System.out.println("TupleHashXOF128: Sample#2");
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        String S = "My Tuple App";
        TupleHash instance = new TupleHashXOF128(256, S);
        byte[] expResult = Bin.toByteArray("3fc8ad69453128292859a18b6c67d7ad85f01b32815e22ce839c49ec374e9b9a");
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
        System.out.println("TupleHashXOF128: Sample#3");
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        byte[] tuple3 = Bin.toByteArray("202122232425262728");
        String S = "My Tuple App";
        TupleHash instance = new TupleHashXOF128(256, S);
        byte[] expResult = Bin.toByteArray("900fe16cad098d28e74d632ed852f99daab7f7df4d99e775657885b4bf76d6f8");
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
        System.out.println("TupleHashXOF256: Sample#4");
        TupleHash instance = new TupleHashXOF256(512, null);
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        byte[] expResult = Bin.toByteArray("03ded4610ed6450a1e3f8bc44951d14fbc384ab0efe57b000df6b6df5aae7cd5"
                + "68e77377daf13f37ec75cf5fc598b6841d51dd207c991cd45d210ba60ac52eb9");
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
        System.out.println("TupleHashXOF256: Sample#5");
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        String S = "My Tuple App";
        TupleHash instance = new TupleHashXOF256(512, S);
        byte[] expResult = Bin.toByteArray("6483cb3c9952eb20e830af4785851fc597ee3bf93bb7602c0ef6a65d741aeca7"
                + "e63c3b128981aa05c6d27438c79d2754bb1b7191f125d6620fca12ce658b2442");
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
        System.out.println("TupleHashXOF256: Sample#6");
        byte[] tuple1 = Bin.toByteArray("000102");
        byte[] tuple2 = Bin.toByteArray("101112131415");
        byte[] tuple3 = Bin.toByteArray("202122232425262728");
        String S = "My Tuple App";
        TupleHash instance = new TupleHashXOF256(512, S);
        byte[] expResult = Bin.toByteArray("0c59b11464f2336c34663ed51b2b950bec743610856f36c28d1d088d8a244628"
                + "4dd09830a6a178dc752376199fae935d86cfdee5913d4922dfd369b66a53c897");
        instance.update(tuple1);
        instance.update(tuple2);
        instance.update(tuple3);
        byte[] result = instance.digest();
        assertArrayEquals(expResult, result);
    }
}
