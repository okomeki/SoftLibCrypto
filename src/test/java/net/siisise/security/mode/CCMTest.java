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

import java.util.Arrays;
import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * CCM Test Vectors
 */
public class CCMTest {
    
    public CCMTest() {
    }

    /**
     * Test of init method, of class CCM.
     */
    @Test
    public void testInit() {
        System.out.println("init");
        byte[][] params = null;
        CCM instance = new CCM(new AES());
//        instance.init(params);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of encrypt method, of class CCM.
     * RFC 3610 8. Test Vectors
     * Packet Vector #1
     */
    @Test
    public void testEncrypt() {
        System.out.println("encrypt");
        byte[] src = Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        byte[] a = Arrays.copyOf(src, 8);
        byte[] m = Arrays.copyOfRange(src, 8, src.length);
        CCM ccm = new CCM(new AES(),8);
        byte[] expResult = Bin.toByteArray("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0");
        byte[] key =   Bin.toByteArray("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        byte[] nonce = Bin.toByteArray("00000003020100a0a1a2a3a4a5");
        ccm.init(key, nonce, a);
        byte[] result = ccm.doFinalEncrypt(m);
        System.out.println(Bin.toHex(result));
        
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of decrypt method, of class CCM.
     */
    @Test
    public void testDecrypt() {
        System.out.println("decrypt");
        CCM instance = new CCM(new AES());
        byte[] src = Bin.toByteArray("588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0");
        byte[] expResult = Bin.toByteArray("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e");
        byte[] a = Arrays.copyOf(expResult, 8);
        byte[] m = Arrays.copyOfRange(expResult, 8, expResult.length);
        CCM ccm = new CCM(new AES(),8);
        byte[] key =   Bin.toByteArray("c0c1c2c3c4c5c6c7c8c9cacbcccdcecf");
        byte[] nonce = Bin.toByteArray("00000003020100a0a1a2a3a4a5");
        ccm.init(key, nonce, a);
        byte[] result = ccm.doFinalDecrypt(src);
        System.out.println(Bin.toHex(result));
        
        assertArrayEquals(m, result);
    }

}
