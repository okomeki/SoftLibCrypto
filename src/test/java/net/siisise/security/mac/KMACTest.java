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
package net.siisise.security.mac;

import net.siisise.lang.Bin;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * KMAC Test.
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/KMAC_samples.pdf
 */
public class KMACTest {
    
    public KMACTest() {
    }
    
    @BeforeAll
    public static void setUpClass() {
    }
    
    @AfterAll
    public static void tearDownClass() {
    }
    
    /**
     * Test of init method, of class KMAC.
     */
    @Test
    public void testSample1() {
        System.out.println("KMAC Sample #1");
        byte[] key = Bin.toByteArray("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] data = Bin.toByteArray("00010203");
        byte[] exResult = Bin.toByteArray("e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e");

        int length = 256;
        String S = null;
        KMAC instance = new KMAC128();
        instance.init(key, length, S);
        byte[] result = instance.doFinal(data);
        assertArrayEquals(exResult,result);
    }

    @Test
    public void testSample2() {
        System.out.println("KMAC Sample #2");
        byte[] key = Bin.toByteArray("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] data = Bin.toByteArray("00010203");
        byte[] exResult = Bin.toByteArray("3b1fba963cd8b0b59e8c1a6d71888b7143651af8ba0a7070c0979e2811324aa5");

        int length = 256;
        String S = "My Tagged Application";
        KMAC instance = new KMAC128();
        instance.init(key, length, S);
        byte[] result = instance.doFinal(data);
        assertArrayEquals(exResult,result);
    }

    @Test
    public void testSample3() {
        System.out.println("KMAC Sample #3");
        byte[] key = Bin.toByteArray("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] data = new byte[200];
        for (int i = 0; i < 200; i++ ) {
            data[i] = (byte)i;
        }
        byte[] exResult = Bin.toByteArray("1f5b4e6cca02209e0dcb5ca635b89a15e271ecc760071dfd805faa38f9729230");

        int length = 256;
        String S = "My Tagged Application";
        KMAC instance = new KMAC128();
        instance.init(key, length, S);
        byte[] result = instance.doFinal(data);
        assertArrayEquals(exResult,result);
    }

    @Test
    public void testSample4() {
        System.out.println("KMAC Sample #4");
        byte[] key = Bin.toByteArray("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] data = Bin.toByteArray("00010203");
        byte[] exResult = Bin.toByteArray("20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7"
                + "f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd");

        int length = 512;
        String S = "My Tagged Application";
        KMAC instance = new KMAC256();
        instance.init(key, length, S);
        byte[] result = instance.doFinal(data);
        assertArrayEquals(exResult,result);
    }

    @Test
    public void testSample5() {
        System.out.println("KMAC Sample #5");
        byte[] key = Bin.toByteArray("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] data = new byte[200];
        for (int i = 0; i < 200; i++ ) {
            data[i] = (byte)i;
        }
        byte[] exResult = Bin.toByteArray("75358cf39e41494e949707927cee0af20a3ff553904c86b08f21cc414bcfd691"
                + "589d27cf5e15369cbbff8b9a4c2eb17800855d0235ff635da82533ec6b759b69");

        int length = 512;
        String S = null;
        KMAC instance = new KMAC256();
        instance.init(key, length, S);
        byte[] result = instance.doFinal(data);
        assertArrayEquals(exResult,result);
    }

    @Test
    public void testSample6() {
        System.out.println("KMAC Sample #6");
        byte[] key = Bin.toByteArray("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f");
        byte[] data = new byte[200];
        for (int i = 0; i < 200; i++ ) {
            data[i] = (byte)i;
        }
        byte[] exResult = Bin.toByteArray("b58618f71f92e1d56c1b8c55ddd7cd188b97b4ca4d99831eb2699a837da2e4d9"
                + "70fbacfde50033aea585f1a2708510c32d07880801bd182898fe476876fc8965");

        int length = 512;
        String S = "My Tagged Application";
        KMAC instance = new KMAC256();
        instance.init(key, length, S);
        byte[] result = instance.doFinal(data);
        assertArrayEquals(exResult,result);
    }
}
