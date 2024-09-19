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
package net.siisise.security.block;

import net.siisise.lang.Bin;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class BlowfishTest {
    
    public BlowfishTest() {
    }

    /**
     * Test of getBlockLength method, of class Blowfish.
     */
    @Test
    public void testGetBlockLength() {
        System.out.println("getBlockLength");
        Blowfish instance = new Blowfish();
        int expResult = 64;
        int result = instance.getBlockLength();
        assertEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class Blowfish.
     */
    @Test
    public void testEncrypt1() {
        System.out.println("encrypt1");
        byte[] src = Bin.toByteArray("0000000000000000");
        byte[] key = Bin.toByteArray("0000000000000000");
//        byte[] src = Bin.toByteArray("0000000100000002");
//        byte[] key = "TESTKEY".getBytes();
        int offset = 0;
        Blowfish instance = new Blowfish();
        instance.init(key);
        byte[] expResult = Bin.toByteArray("4ef997456198dd78");
        byte[] result = instance.encrypt(src, offset);
        System.out.println(Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of decrypt method, of class Blowfish.
     */
    @Test
    public void testDecrypt1() {
        System.out.println("encrypt1");
        byte[] src = Bin.toByteArray("4ef997456198dd78");
        byte[] key = Bin.toByteArray("0000000000000000");
//        byte[] src = Bin.toByteArray("0000000100000002");
//        byte[] key = "TESTKEY".getBytes();
        int offset = 0;
        Blowfish instance = new Blowfish();
        instance.init(key);
        byte[] expResult = Bin.toByteArray("0000000000000000");
        byte[] result = instance.decrypt(src, offset);
        System.out.println(Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class Blowfish.
     */
    @Test
    public void testEncrypt2() {
        System.out.println("encrypt2");
        byte[] src = Bin.toByteArray("ffffffffffffffff");
        byte[] key = Bin.toByteArray("ffffffffffffffff");
//        byte[] src = Bin.toByteArray("0000000100000002");
//        byte[] key = "TESTKEY".getBytes();
        int offset = 0;
        Blowfish instance = new Blowfish();
        instance.init(key);
        byte[] expResult = Bin.toByteArray("51866fd5b85ecb8a");
        byte[] result = instance.encrypt(src, offset);
        System.out.println(Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class Blowfish.
     */
    @Test
    public void testEncrypt3() {
        System.out.println("encrypt3");
        byte[] src = Bin.toByteArray("1000000000000001");
        byte[] key = Bin.toByteArray("3000000000000000");
//        byte[] src = Bin.toByteArray("0000000100000002");
//        byte[] key = "TESTKEY".getBytes();
        int offset = 0;
        Blowfish instance = new Blowfish();
        instance.init(key);
        byte[] expResult = Bin.toByteArray("7d856f9a613063f2");
        byte[] result = instance.encrypt(src, offset);
        System.out.println(Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }
}
