/*
 * Copyright 2022 okome.
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
package net.siisise.ietf.pkcs5;

import net.siisise.lang.Bin;
import net.siisise.security.digest.SHA1;
import net.siisise.security.mac.HMAC;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * RFC 8018 PKCS #5: Password-Based Cryptography Specification 2.1
 * RFC 6070 PKCS #5: Password-Based Key Derivation Function 2 (PBKDF2)
 * Test Vectors
 * 
 */
public class PBKDF2Test {
    
    public PBKDF2Test() {
    }

    /**
     * Wikipedia の
     */
    @Test
    public void testSomeMethod() {
        System.out.println("PKCS#5 PBKDF2 Wikipedia");
        byte[] password = "plnlrtfpijpuhqylxbgqiiyipieyxvfsavzgxbbcfusqkozwpngsyejqlmjsytrmd".getBytes();
        String saltHex = "A009C1A485912C6AE630D3E744240B04";
        byte[] dkExpected = Bin.toByteArray("17EB4014C8C461C300E9B61518B9A18B");
        
        HMAC prf = new HMAC(new SHA1());
        byte[] salt = Bin.toByteArray(saltHex); // 仮
        int c = 1000;
        int dkLen = 16;
        byte[] actual = PBKDF2.pbkdf2(prf, password, salt, c, dkLen);
        
        assertArrayEquals(dkExpected,actual);
    }
    
    @Test
    public void test2_1() {
        System.out.println("PKCS#5 PBKDF2 Test 1");
        HMAC prf = new HMAC(new SHA1());
        
        byte[] p = "password".getBytes();
        byte[] salt = "salt".getBytes();
        int c = 1;
        int dkLen = 20;
        byte[] dkEx = Bin.toByteArray("0c60c80f961f0e71f3a9b524af6012062fe037a6");
        
        byte[] dkActual = PBKDF2.pbkdf2(prf, p, salt, c, dkLen);
        
        assertArrayEquals(dkEx, dkActual);
    }

    @Test
    public void test2_2() {
        System.out.println("PKCS#5 PBKDF2 Test 2");
        HMAC prf = new HMAC(new SHA1());
        
        byte[] p = "password".getBytes();
        byte[] salt = "salt".getBytes();
        int c = 2;
        int dkLen = 20;
        byte[] dkEx = Bin.toByteArray("ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957");
        
        byte[] dkActual = PBKDF2.pbkdf2(prf, p, salt, c, dkLen);
        
        assertArrayEquals(dkEx, dkActual);
    }
    
    @Test
    public void test2_3() {
        System.out.println("PKCS#5 PBKDF2 Test 3");
        HMAC prf = new HMAC(new SHA1());
        
        byte[] p = "password".getBytes();
        byte[] salt = "salt".getBytes();
        int c = 4096;
        int dkLen = 20;
        byte[] dkEx = Bin.toByteArray("4b007901b765489abead49d926f721d065a429c1");
        
        byte[] dkActual = PBKDF2.pbkdf2(prf, p, salt, c, dkLen);
        
        assertArrayEquals(dkEx, dkActual);
    }

    @Test
    public void test2_4() {
        System.out.println("PKCS#5 PBKDF2 Test 4");
        HMAC prf = new HMAC(new SHA1());
        
        byte[] p = "password".getBytes();
        byte[] salt = "salt".getBytes();
        int c = 16777216;
        int dkLen = 20;
        byte[] dkEx = Bin.toByteArray("eefe3d61cd4da4e4e9945b3d6ba2158c2634e984");
        
        byte[] dkActual = PBKDF2.pbkdf2(prf, p, salt, c, dkLen);
        
        assertArrayEquals(dkEx, dkActual);
    }

    @Test
    public void test2_5() {
        System.out.println("PKCS#5 PBKDF2 Test 5");
        HMAC prf = new HMAC(new SHA1());
        
        byte[] p = "passwordPASSWORDpassword".getBytes();
        byte[] salt = "saltSALTsaltSALTsaltSALTsaltSALTsalt".getBytes();
        int c = 4096;
        int dkLen = 25;
        byte[] dkEx = Bin.toByteArray("3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
        
        byte[] dkActual = PBKDF2.pbkdf2(prf, p, salt, c, dkLen);
        
        assertArrayEquals(dkEx, dkActual);
    }

    @Test
    public void test2_6() {
        System.out.println("PKCS#5 PBKDF2 Test 6");
        HMAC prf = new HMAC(new SHA1());
        
        byte[] p = "pass\0word".getBytes();
        byte[] salt = "sa\0lt".getBytes();
        int c = 4096;
        int dkLen = 16;
        byte[] dkEx = Bin.toByteArray("56fa6aa75548099dcc37d7f03425e0c3");
        
        byte[] dkActual = PBKDF2.pbkdf2(prf, p, salt, c, dkLen);
        
        assertArrayEquals(dkEx, dkActual);
    }
}
