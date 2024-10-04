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

import net.siisise.io.BASE64;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class BCryptTest {
    
    public BCryptTest() {
    }

    /**
     * Test of gen method, of class BCrypt.
     */
    @Test
    public void testGen() throws Exception {
        System.out.println("gen");
        int cost = BCrypt.DEFAULT_COST;
        String pass = "test";
        BCrypt instance = new BCrypt();
        String expResult = "";
        String result = instance.gen(cost, pass);
        System.out.println(result);
//        assertEquals(expResult, result);
    }

    /**
     * Test of encode method, of class BCrypt.
     */
    @Test
    public void testEncode() {
        System.out.println("encode");
        int cost = BCrypt.DEFAULT_COST;
        BASE64 m = new BASE64(BASE64.BCRYPT,0);
        byte[] salt = m.decode("GhvMmNVjRW29ulnudl.Lbu");
        String pass = "password";
        BCrypt instance = new BCrypt();
        String expResult = "$2b$" + cost + "$" + m.encode(salt)+"AnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m";
        String result = instance.encode(cost, salt, pass);
        System.out.println(expResult);
        System.out.println(result);
        assertEquals(expResult, result);
    }

    /**
     * Test of verify method, of class BCrypt.
     */
    @Test
    public void testVeryfy() {
        System.out.println("veryfy");
        String pass = "password";
        String code = "$2b$12$GhvMmNVjRW29ulnudl.LbuAnUtN/LRfe1JsBm1Xu6LE3059z5Tr8m";
        BCrypt instance = new BCrypt();
        boolean expResult = true;
        boolean result = instance.verify(pass, code);
        assertEquals(expResult, result);
    }
    
}
