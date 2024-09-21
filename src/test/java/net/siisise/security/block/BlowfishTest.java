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
 * Blowfish Test Vectors
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

    static int[][][] testVectors = {
        {{0x00000000,0x00000000},{0x00000000,0x00000000},{0x4ef99745,0x6198dd78}},
        {{0xffffffff,0xffffffff},{0xffffffff,0xffffffff},{0x51866fd5,0xb85ecb8a}},
        {{0x30000000,0x00000000},{0x10000000,0x00000001},{0x7d856f9a,0x613063f2}},
        {{0x11111111,0x11111111},{0x11111111,0x11111111},{0x2466dd87,0x8b963c9d}},
        {{0x01234567,0x89abcdef},{0x11111111,0x11111111},{0x61f9c380,0x2281b096}},
        {{0x11111111,0x11111111},{0x01234567,0x89abcdef},{0x7d0cc630,0xafda1ec7}},
        {{0x00000000,0x00000000},{0x00000000,0x00000000},{0x4ef99745,0x6198dd78}},
        {{0xfedcba98,0x76543210},{0x01234567,0x89abcdef},{0x0aceab0f,0xc6a0a28d}},
        {{0x7CA11045,0x4A1A6E57},{0x01A1D6D0,0x39776742},{0x59C68245,0xEB05282B}},
        {{0x0131D961,0x9DC1376E},{0x5CD54CA8,0x3DEF57DA},{0xB1B8CC0B,0x250F09A0}},
        {{0x07A1133E,0x4A0B2686},{0x0248D438,0x06F67172},{0x1730E577,0x8BEA1DA4}},
        {{0x3849674C,0x2602319E},{0x51454B58,0x2DDF440A},{0xA25E7856,0xCF2651EB}},
        {{0x04B915BA,0x43FEB5B6},{0x42FD4430,0x59577FA2},{0x353882B1,0x09CE8F1A}},
        {{0x0113B970,0xFD34F2CE},{0x059B5E08,0x51CF143A},{0x48F4D088,0x4C379918}},
        {{0x0170F175,0x468FB5E6},{0x0756D8E0,0x774761D2},{0x432193B7,0x8951FC98}},
        {{0x43297FAD,0x38E373FE},{0x762514B8,0x29BF486A},{0x13F04154,0xD69D1AE5}},
        {{0x07A71370,0x45DA2A16},{0x3BDD1190,0x49372802},{0x2EEDDA93,0xFFD39C79}},
        {{0x04689104,0xC2FD3B2F},{0x26955F68,0x35AF609A},{0xD887E039,0x3C2DA6E3}},
        {{0x37D06BB5,0x16CB7546},{0x164D5E40,0x4F275232},{0x5F99D04F,0x5B163969}},
        {{0x1F08260D,0x1AC2465E},{0x6B056E18,0x759F5CCA},{0x4A057A3B,0x24D3977B}},
        {{0x58402364,0x1ABA6176},{0x004BD6EF,0x09176062},{0x452031C1,0xE4FADA8E}},
        {{0x02581616,0x4629B007},{0x480D3900,0x6EE762F2},{0x7555AE39,0xF59B87BD}},
        {{0x49793EBC,0x79B3258F},{0x437540C8,0x698F3CFA},{0x53C55F9C,0xB49FC019}},
        {{0x4FB05E15,0x15AB73A7},{0x072D43A0,0x77075292},{0x7A8E7BFA,0x937E89A3}},
        {{0x49E95D6D,0x4CA229BF},{0x02FE5577,0x8117F12A},{0xCF9C5D7A,0x4986ADB5}},
        {{0x018310DC,0x409B26D6},{0x1D9D5C50,0x18F728C2},{0xD1ABB290,0x658BC778}},
        {{0x1C587F1C,0x13924FEF},{0x30553228,0x6D6F295A},{0x55CB3774,0xD13EF201}},
        {{0x01010101,0x01010101},{0x01234567,0x89ABCDEF},{0xFA34EC48,0x47B268B2}},
        {{0x1F1F1F1F,0x0E0E0E0E},{0x01234567,0x89ABCDEF},{0xA7907951,0x08EA3CAE}},
        {{0xE0FEE0FE,0xF1FEF1FE},{0x01234567,0x89ABCDEF},{0xC39E072D,0x9FAC631D}},
        {{0x00000000,0x00000000},{0xFFFFFFFF,0xFFFFFFFF},{0x014933E0,0xCDAFF6E4}},
        {{0xFFFFFFFF,0xFFFFFFFF},{0x00000000,0x00000000},{0xF21E9A77,0xB71C49BC}},
        {{0x01234567,0x89ABCDEF},{0x00000000,0x00000000},{0x24594688,0x5754369A}},
        {{0xFEDCBA98,0x76543210},{0xFFFFFFFF,0xFFFFFFFF},{0x6B5C5A9C,0x5D9E0A5A}}
    };

    /**
     * Test of decrypt method, of class Blowfish.
     */
    @Test
    public void testEncrypt() {
        System.out.println("encrypt");
        Blowfish instance = new Blowfish();
        for ( int[][] s : testVectors ) {
            byte[] key = Bin.itob(s[0]);
            int[] plaintext = s[1];
            int[] ciphertext = s[2];
            instance.init(key);
            int[] result = instance.encrypt(plaintext);
            System.out.print("key: " + Bin.toHex(key));
            System.out.print(" plaintext:"  + Bin.toHex(Bin.itob(plaintext)));
            System.out.print(" ciphertext:"  + Bin.toHex(Bin.itob(ciphertext)));
            System.out.println(" result:"  + Bin.toHex(Bin.itob(result)));
            assertArrayEquals(ciphertext,result);
        }
    }
    
    /**
     * Test of decrypt method, of class Blowfish.
     */
    @Test
    public void testDecrypt() {
        System.out.println("decrypt");
        Blowfish instance = new Blowfish();
        for ( int[][] s : testVectors ) {
            byte[] key = Bin.itob(s[0]);
            int[] plaintext = s[1];
            int[] ciphertext = s[2];
            instance.init(key);
            int[] result = instance.decrypt(ciphertext);
            System.out.print("key: " + Bin.toHex(key));
            System.out.print(" plaintext:"  + Bin.toHex(Bin.itob(plaintext)));
            System.out.print(" ciphertext:"  + Bin.toHex(Bin.itob(ciphertext)));
            System.out.println(" result:"  + Bin.toHex(Bin.itob(result)));
            assertArrayEquals(plaintext,result);
        }
    }
}
