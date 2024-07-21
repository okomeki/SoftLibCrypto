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
package net.siisise.security.mode;

import net.siisise.security.block.AES;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class PKCS7PaddingTest {

    public PKCS7PaddingTest() {
    }

    /**
     * Test of getParamLength method, of class PKCS7EncodePadding.
     */
    @Test
    public void testGetParamLength() {
        System.out.println("getParamLength");
        PKCS7Padding instance = new PKCS7Padding(new CBC(new AES(256)));
        int[] expResult = new int[]{256, 128};
        int[] result = instance.getParamLength();
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of init method, of class PKCS7EncodePadding.
     */
    @Test
    public void testInit() {
        System.out.println("init");
        byte[][] keyandparam = null;
        PKCS7Padding instance = new PKCS7Padding(new CBC(new AES()));
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        instance.init(key, iv);
    }

    /**
     * Test of getBlockLength method, of class PKCS7EncodePadding.
     */
    @Test
    public void testGetBlockLength() {
        System.out.println("getBlockLength");
        PKCS7Padding instance = new PKCS7Padding(new CBC(new AES()));
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        instance.init(key, iv);
        int expResult = 128;
        int result = instance.getBlockLength();
        assertEquals(expResult, result);
    }

    /**
     * Test of doFinalEncrypt method, of class PKCS7EncodePadding.
     */
    @Test
    public void testDoFinalEncrypt() {
        System.out.println("doFinalEncrypt");
        byte[] src = {0};
        int offset = 0;
        int length = 1;
        PKCS7Padding instance = new PKCS7Padding(new CBC(new AES()));
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        instance.init(key, iv);
        byte[] expResult = {122, -36, -103, -78, -98, -126, -79, -78, -80, -90, 90, 56, -68, 87, -118, 1};
        byte[] result = instance.doFinalEncrypt(src, offset, length);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of doFinalDecrypt method, of class PKCS7EncodePadding.
     */
    @Test
    public void testDoFinalDecrypt() {
        System.out.println("doFinalDecrypt");
        byte[] src = {122, -36, -103, -78, -98, -126, -79, -78, -80, -90, 90, 56, -68, 87, -118, 1};
        int offset = 0;
        int length = 16;
        PKCS7Padding instance = new PKCS7Padding(new CBC(new AES()));
        byte[] key = new byte[16];
        byte[] iv = new byte[16];
        instance.init(key, iv);
        byte[] expResult = {0};
        byte[] result = instance.doFinalDecrypt(src, offset, length);
        assertArrayEquals(expResult, result);
    }

}
