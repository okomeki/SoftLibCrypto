/*
 * Copyright 2023 okome.
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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

/**
 *
 * @author okome
 */
public class OMAC2Test {
    
    public OMAC2Test() {
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

    /*
     * Test of initk method, of class OMAC2.
     * いろいろOMAC1用なので使えない
     * http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/tv/omac2-tv.txt
     */

    @Test
    public void testIwata() {
        System.out.println("OMAC2 Test Vectors");
//        byte[] L = Bin.toByteArray("7df76b0c1ab899b33e42f047b91b546f");
        byte[] Lu = Bin.toByteArray("fbeed618357133667c85e08f7236a8de");
        byte[] Lum = Bin.toByteArray("befbb5860d5c4cd99f217823dc8daa74");
        System.out.println(" empty");
        byte[] Key = Bin.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] exTag = Bin.toByteArray("f6bc6a41f4f84593809e59b719299cfe");
//        GF gf = new GF(128, GF.FF128);
        OMAC2 omac = new OMAC2();
        omac.init(Key);
        System.out.println(Bin.toHex(omac.k1));
        assertArrayEquals(Lu,omac.k1);
        System.out.println(Bin.toHex(omac.k2));
        assertArrayEquals(Lum,omac.k2);
        byte[] T = omac.sign();
        System.out.println(Bin.toHex(T));
        assertArrayEquals(exTag, T);
        System.out.println(" 16-byte string");
        //Key = Bin.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] Msg = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a");
        exTag = Bin.toByteArray("070a16b46b4d4144f79bdd9dd04a287c");
        T = omac.doFinal(Msg);
        assertArrayEquals(exTag, T);
        Msg = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411");
        exTag = Bin.toByteArray("23fdaa0831cd314491ce4b25acb6023b");
        T = omac.doFinal(Msg);
        assertArrayEquals(exTag, T);
        Msg = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
        exTag = Bin.toByteArray("51f0bebf7e3b9d92fc49741779363cfe");
        T = omac.doFinal(Msg);
        assertArrayEquals(exTag, T);

        Key = Bin.toByteArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        omac.init(Key);
        exTag = Bin.toByteArray("149f579df2129d45a69266898f55aeb2");
        T = omac.sign();
        assertArrayEquals(exTag, T);
        Msg = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a");
        exTag = Bin.toByteArray("9e99a7bf31e710900662f65e617c5184");
        T = omac.doFinal(Msg);
        assertArrayEquals(exTag, T);
        
    }
    
}
