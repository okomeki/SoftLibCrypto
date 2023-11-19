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
package net.siisise.security.digest;

import net.siisise.lang.Bin;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class cSHAKETest {
    
    public cSHAKETest() {
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

    @Test
    public void testSample1() {
        System.out.println("cSHAKE Sample #1");
        byte[] data = Bin.toByteArray("00010203");
        byte[] example = Bin.toByteArray("c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5");
        String N = "";
        String S = "Email Signature";
        cSHAKE cSHAKE = new cSHAKE128(256, N, S);
        cSHAKE.update(data);
        byte[] hash = cSHAKE.digest();
        assertArrayEquals(example, hash);
    }
    
   @Test
    public void testSample2() {
        System.out.println("cSHAKE Sample #2");
        byte[] data = new byte[0xc8];
        for (int i = 0; i < 0xc8; i++) {
            data[i] = (byte)i;
        }
        byte[] example = Bin.toByteArray("c5221d50e4f822d96a2e8881a961420f294b7b24fe3d2094baed2c6524cc166b");
        String N = "";
        String S = "Email Signature";
        cSHAKE cSHAKE = new cSHAKE128(256, N, S);
        cSHAKE.update(data);
        byte[] hash = cSHAKE.digest();
        assertArrayEquals(example, hash);
    }

    @Test
    public void testSample3() {
        System.out.println("cSHAKE Sample #3");
        byte[] data = Bin.toByteArray("00010203");
        byte[] example = Bin.toByteArray("d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c");
        String N = "";
        String S = "Email Signature";
        cSHAKE cSHAKE = new cSHAKE256(512, N, S);
        cSHAKE.update(data);
        byte[] hash = cSHAKE.digest();
        assertArrayEquals(example, hash);
    }

    @Test
    public void testSample4() {
        System.out.println("cSHAKE Sample #4");
        byte[] data = new byte[0xc8];
        for (int i = 0; i < 0xc8; i++) {
            data[i] = (byte)i;
        }
        byte[] example = Bin.toByteArray("07dc27b11e51fbac75bc7b3c1d983e8b4b85fb1defaf218912ac86430273091727f42b17ed1df63e8ec118f04b23633c1dfb1574c8fb55cb45da8e25afb092bb");
        String N = "";
        String S = "Email Signature";
        cSHAKE cSHAKE = new cSHAKE256(512, N, S);
        cSHAKE.update(data);
        byte[] hash = cSHAKE.digest();
        assertArrayEquals(example, hash);
    }
}
