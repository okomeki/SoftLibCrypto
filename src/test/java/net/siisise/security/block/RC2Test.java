/*
 * Copyright 2023 Siisise Net.
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
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 * RFC 2268
 * @author okome
 */
public class RC2Test {
    
    public RC2Test() {
    }

    @Test
    public void testEnc() {
        System.out.println("RC2 encrypt 1");
        byte[] key   = {0,0,0,0,0,0,0,0};
        byte[] plane = {0,0,0,0,0,0,0,0};
        byte[] ex = {(byte)0xeb,(byte)0xb7,0x73,(byte)0xf9, (byte)0x93,0x27,(byte)0x8e,(byte)0xff};
        RC2 rc2 = new RC2();
        rc2.setKeyBitLength(63);
        rc2.init(key);
        byte[] e = rc2.encrypt(plane, 0);
//        FileIO.dump(ex);
//        FileIO.dump(e);
        assertArrayEquals(ex, e);
        byte[] d = rc2.decrypt(e, 0);
        assertArrayEquals(plane, d);
    }

    @Test
    public void testEnc2() {
        System.out.println("RC2 encrypt 2");
        byte[] key   = Bin.toByteArray("ffffffffffffffff");
        byte[] plane = Bin.toByteArray("ffffffffffffffff");
        byte[] ex = new byte[] {0x27,(byte)0x8b,0x27,(byte)0xe4, 0x2e,0x2f,0x0d,0x49};
        RC2 rc2 = new RC2();
        rc2.init(key);
        byte[] e = rc2.encrypt(plane, 0);
        assertArrayEquals(ex, e);
        byte[] d = rc2.decrypt(e, 0);
        assertArrayEquals(plane, d);
    }

    @Test
    public void testEnc3() {
        System.out.println("RC2 encrypt 3");
        byte[] key   = Bin.toByteArray("3000000000000000");
        byte[] plane = Bin.toByteArray("1000000000000001");
        byte[] ex = Bin.toByteArray("30649edf9be7d2c2");
        RC2 rc2 = new RC2();
        rc2.init(key);
        byte[] e = rc2.encrypt(plane, 0);
        assertArrayEquals(ex, e);
        byte[] d = rc2.decrypt(e, 0);
        assertArrayEquals(plane, d);
    }

    @Test
    public void testEnc4() {
        System.out.println("RC2 encrypt 4");
        byte[] key   = Bin.toByteArray("88");
        byte[] plane = Bin.toByteArray("0000000000000000");
        byte[] ex = Bin.toByteArray("61a8a244adacccf0");
        RC2 rc2 = new RC2();
        rc2.init(key);
        byte[] e = rc2.encrypt(plane, 0);
        assertArrayEquals(ex, e);
        byte[] d = rc2.decrypt(e, 0);
        assertArrayEquals(plane, d);
    }

    @Test
    public void testEnc5() {
        System.out.println("RC2 encrypt 5");
        byte[] key   = Bin.toByteArray("88bca90e90875a");
        byte[] plane = Bin.toByteArray("0000000000000000");
        byte[] ex = Bin.toByteArray("6ccf4308974c267f");
        RC2 rc2 = new RC2();
        rc2.init(key);
        byte[] e = rc2.encrypt(plane, 0);
        assertArrayEquals(ex, e);
        byte[] d = rc2.decrypt(e, 0);
        assertArrayEquals(plane, d);
    }

    @Test
    public void testEnc6() {
        System.out.println("RC2 encrypt 6");
        byte[] key   = Bin.toByteArray("88bca90e90875a7f0f79c384627bafb2");
        byte[] plane = Bin.toByteArray("0000000000000000");
        byte[] ex = Bin.toByteArray("1a807d272bbe5db1");
        RC2 rc2 = new RC2();
        rc2.init(key);
        byte[] e = rc2.encrypt(plane, 0);
        assertArrayEquals(ex, e);
        byte[] d = rc2.decrypt(e, 0);
        assertArrayEquals(plane, d);
    }

    @Test
    public void testEnc7() {
        System.out.println("RC2 encrypt 7");
        byte[] key   = Bin.toByteArray("88bca90e90875a7f0f79c384627bafb2");
        byte[] plane = Bin.toByteArray("0000000000000000");
        byte[] ex = Bin.toByteArray("2269552ab0f85ca6");
        RC2 rc2 = new RC2();
        rc2.setKeyBitLength(128);
        rc2.init(key);
        byte[] e = rc2.encrypt(plane, 0);
        assertArrayEquals(ex, e);
        byte[] d = rc2.decrypt(e, 0);
        assertArrayEquals(plane, d);
    }

    @Test
    public void testEnc8() {
        System.out.println("RC2 encrypt 8");
        byte[] key   = Bin.toByteArray("88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e");
        byte[] plane = Bin.toByteArray("0000000000000000");
        byte[] ex = Bin.toByteArray("5b78d3a43dfff1f1");
        RC2 rc2 = new RC2();
        rc2.setKeyBitLength(129);
        rc2.init(key);
        byte[] e = rc2.encrypt(plane, 0);
        assertArrayEquals(ex, e);
        byte[] d = rc2.decrypt(e, 0);
        assertArrayEquals(plane, d);
    }

    /**
     * Test of getBlockLength method, of class RC2.
     */
    @Test
    public void testGetBlockLength() {
        System.out.println("getBlockLength");
        RC2 instance = new RC2();
        int expResult = 64;
        int result = instance.getBlockLength();
        assertEquals(expResult, result);
    }

    /**
     * Test of encrypt method, of class RC2.
     */
/*
    @Test
    public void testEncrypt() {
        System.out.println("encrypt");
        byte[] src = null;
        int offset = 0;
        RC2 instance = new RC2();
        byte[] expResult = null;
        byte[] result = instance.encrypt(src, offset);
        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
*/
    /**
     * Test of decrypt method, of class RC2.
     */
/*
    @Test
    public void testDecrypt() {
        System.out.println("decrypt");
        byte[] src = null;
        int offset = 0;
        RC2 instance = new RC2();
        byte[] expResult = null;
        byte[] result = instance.decrypt(src, offset);
        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
*/    
}
