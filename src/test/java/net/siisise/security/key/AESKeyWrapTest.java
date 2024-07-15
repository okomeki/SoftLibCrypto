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
package net.siisise.security.key;

import net.siisise.lang.Bin;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * AES Key Wrap Test
 */
public class AESKeyWrapTest {
    
    public AESKeyWrapTest() {
    }

    /**
     * Test of encrypt method, of class AESKeyWrap.
     */
    @Test
    public void testEncrypt1() {
        System.out.println("encrypt1 128 128");
        byte[] plain = Bin.toByteArray("00112233445566778899aabbccddeeff");
        AESKeyWrap instance = new AESKeyWrap();
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f"));
        byte[] expResult = Bin.toByteArray("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        byte[] result = instance.encrypt(plain);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class AESKeyWrap.
     */
    @Test
    public void testDecrypt1() {
        System.out.println("decrypt1 128 128");
        byte[] ciphertext = Bin.toByteArray("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");
        AESKeyWrap instance = new AESKeyWrap();
        byte[] expResult = Bin.toByteArray("00112233445566778899aabbccddeeff");
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f"));
        byte[] result = instance.decrypt(ciphertext);
        assertArrayEquals(expResult, result);
    }
    
    /**
     * Test of encrypt method, of class AESKeyWrap.
     */
    @Test
    public void testEncrypt2() {
        System.out.println("encrypt2 192 128");
        byte[] plain = Bin.toByteArray("00112233445566778899aabbccddeeff");
        AESKeyWrap instance = new AESKeyWrap();
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f1011121314151617"));
        byte[] expResult = Bin.toByteArray("96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d");
        byte[] result = instance.encrypt(plain);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class AESKeyWrap.
     */
    @Test
    public void testDecrypt2() {
        System.out.println("decrypt2 192 128");
        byte[] ciphertext = Bin.toByteArray("96778b25ae6ca435f92b5b97c050aed2468ab8a17ad84e5d");
        AESKeyWrap instance = new AESKeyWrap();
        byte[] expResult = Bin.toByteArray("00112233445566778899aabbccddeeff");
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f1011121314151617"));
        byte[] result = instance.decrypt(ciphertext);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of encrypt method, of class AESKeyWrap.
     */
    @Test
    public void testEncrypt3() {
        System.out.println("encrypt3 256 128");
        byte[] plain = Bin.toByteArray("00112233445566778899aabbccddeeff");
        AESKeyWrap instance = new AESKeyWrap();
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        byte[] expResult = Bin.toByteArray("64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7");
        byte[] result = instance.encrypt(plain);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class AESKeyWrap.
     */
    @Test
    public void testDecrypt3() {
        System.out.println("decrypt3 256 128");
        byte[] ciphertext = Bin.toByteArray("64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7");
        AESKeyWrap instance = new AESKeyWrap();
        byte[] expResult = Bin.toByteArray("00112233445566778899aabbccddeeff");
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        byte[] result = instance.decrypt(ciphertext);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of encrypt method, of class AESKeyWrap.
     */
    @Test
    public void testEncrypt4() {
        System.out.println("encrypt4 192 192");
        byte[] plain = Bin.toByteArray("00112233445566778899aabbccddeeff0001020304050607");
        AESKeyWrap instance = new AESKeyWrap();
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f1011121314151617"));
        byte[] expResult = Bin.toByteArray("031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2");
        byte[] result = instance.encrypt(plain);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class AESKeyWrap.
     */
    @Test
    public void testDecrypt4() {
        System.out.println("decrypt4 192 192");
        byte[] ciphertext = Bin.toByteArray("031d33264e15d33268f24ec260743edce1c6c7ddee725a936ba814915c6762d2");
        AESKeyWrap instance = new AESKeyWrap();
        byte[] expResult = Bin.toByteArray("00112233445566778899aabbccddeeff0001020304050607");
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f1011121314151617"));
        byte[] result = instance.decrypt(ciphertext);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of encrypt method, of class AESKeyWrap.
     */
    @Test
    public void testEncrypt5() {
        System.out.println("encrypt5 256 192");
        byte[] plain = Bin.toByteArray("00112233445566778899aabbccddeeff0001020304050607");
        AESKeyWrap instance = new AESKeyWrap();
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        byte[] expResult = Bin.toByteArray("a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1");
        byte[] result = instance.encrypt(plain);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class AESKeyWrap.
     */
    @Test
    public void testDecrypt5() {
        System.out.println("decrypt5 256 192");
        byte[] ciphertext = Bin.toByteArray("a8f9bc1612c68b3ff6e6f4fbe30e71e4769c8b80a32cb8958cd5d17d6b254da1");
        AESKeyWrap instance = new AESKeyWrap();
        byte[] expResult = Bin.toByteArray("00112233445566778899aabbccddeeff0001020304050607");
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        byte[] result = instance.decrypt(ciphertext);
        assertArrayEquals(expResult, result);
    }


    /**
     * Test of encrypt method, of class AESKeyWrap.
     */
    @Test
    public void testEncrypt6() {
        System.out.println("encrypt5 256 256");
        byte[] plain = Bin.toByteArray("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        AESKeyWrap instance = new AESKeyWrap();
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        byte[] expResult = Bin.toByteArray("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");
        byte[] result = instance.encrypt(plain);
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class AESKeyWrap.
     */
    @Test
    public void testDecrypt6() {
        System.out.println("decrypt6 256 256");
        byte[] ciphertext = Bin.toByteArray("28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326cbc7f0e71a99f43bfb988b9b7a02dd21");
        AESKeyWrap instance = new AESKeyWrap();
        byte[] expResult = Bin.toByteArray("00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f");
        instance.init(Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"));
        byte[] result = instance.decrypt(ciphertext);
        assertArrayEquals(expResult, result);
    }
}
