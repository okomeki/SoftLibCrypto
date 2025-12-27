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
package net.siisise.security.key.mcf;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * sha256_crypt
 * sha512_crypt
 */
public class DigestCryptTest {
    
    public DigestCryptTest() {
    }

    /**
     * Test of generate method, of class DigestCrypt.
     */
    @Test
    public void testGenerate() {
        System.out.println("generate");
        String pass = "test";
        DigestCrypt instance = new DigestCrypt("6","sha-512");
        String result = instance.generate(pass);
        System.out.println(result);
        
        boolean very = instance.verify(pass, result);
        assertTrue(very);
    }

    /**
     * Test of verify method, of class DigestCrypt.
     */
    @Test
    public void testVerify1() {
        System.out.println("verify md5");
        String pass = "password";
        String code = "$1$5pZSV9va$azfrPr6af3Fc7dLblQXVa0";
        DigestCrypt instance = new DigestCrypt("1", "md5");
        boolean expResult = true;
        boolean result = instance.verify(pass, code);
        System.out.println(code);
//        assertTrue(result);
    }

    /**
     * Test of verify method, of class DigestCrypt.
     */
    @Test
    public void testVerify5() {
        System.out.println("verify sha-256");
        String pass = "password";
        String code = "$5$rounds=80000$wnsT7Yr92oJoP28r$cKhJImk5mfuSKV9b3mumNzlbstFUplKtQXXMo4G6Ep5";
        DigestCrypt instance = new DigestCrypt("5", "sha-256");
        boolean expResult = true;
        boolean result = instance.verify(pass, code);
        System.out.println(code);
        assertTrue(result);
    }

    /**
     * Test of verify method, of class DigestCrypt.
     */
    @Test
    public void testVerify52() {
        System.out.println("verify sha-256 2");
        String pass = "password";
        String code = "$5$rounds=12345$q3hvJE5mn5jKRsW.$BbbYTFiaImz9rTy03GGi.Jf9YY5bmxN0LU3p3uI1iUB";
        DigestCrypt instance = new DigestCrypt("5", "sha-256");
        boolean expResult = true;
        boolean result = instance.verify(pass, code);
        System.out.println(code);
        assertTrue(result);
    }

    /**
     * Test of verify method, of class DigestCrypt.
     */
    @Test
    public void testVerify6() {
        System.out.println("verify sha512");
        String pass = "test";
        String code = "$6$salt$xdLuw21n.5WciQUUpHTTPfR6QwS..Z1Q/4xGfiyYa51WSQktzSXYXSk2zBp.Is5r9WiXrGqRmHpEG0iG0HaSk.";
        DigestCrypt instance = new DigestCrypt("6", "sha-512");
        boolean expResult = true;
        boolean result = instance.verify(pass, code);
        System.out.println(code);
        assertTrue(result);
    }
}
