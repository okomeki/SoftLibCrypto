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

import net.siisise.io.FileIO;
import net.siisise.lang.Bin;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 * https://www.ipa.go.jp/files/000013698.pdf
 * [23] NIST SP 800-17 MOVS https://csrc.nist.gov/publications/detail/sp/800-17/archive/1998-02-01
 */
public class DESTest {
    
    public DESTest() {
    }

    /**
     * Test of getBlockLength method, of class DES.
     */
    @Test
    public void testGetBlockLength() {
        System.out.println("getBlockLength");
        DES des = new DES();
        int expResult = 64;
        int result = des.getBlockLength();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of encrypt method, of class DES.
     */
    @Test
    public void testEncrypt() {
        System.out.println("encrypt");
        DES des = new DES();
        byte[] expResult = Bin.toByteArray("82dcbafbdeab6602");
//        byte[] result = des.encrypt(src, offset);

        System.out.println("NIST 800-17 Appendix A Sample Round Outputs for the DES");
        byte[] key = new byte[] {0x10,0x31,0x6e,0x02,(byte)0x8c,(byte)0x8f,0x3b,0x4a};
        des.init(key);
        byte[] x = des.encrypt(new byte[8],0);
        FileIO.dump(x);
        assertArrayEquals(expResult, x);
        
        System.out.println("NIST END -------------");

        byte[] in8 = {0x41,0x7a, 0x61, 0x74, 0x68,0x6f, 0x74, 0x68 };
        
        
        des.init(new byte[] {0,3,6,9,0,3,6,9});
        x = des.encrypt(in8, 0);
//        HMACTest.dump(in8);
//        HMACTest.dump(x);
        byte[] x2 = des.decrypt(x, 0);
//        HMACTest.dump(ex);
        assertArrayEquals(in8, x2);
        
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
}
