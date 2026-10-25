/*
 * Copyright 2026 okome.
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
 *
 */
public class DEScryptTest {
    
    public DEScryptTest() {
    }
    
    /**
     * Test of generate method, of class DEScrypt.
     */
    @Test
    public void testGenerate() {
        System.out.println("generate");
        String pass = "password";
        DEScrypt desc = new DEScrypt();
        String expResult = "JQMuyS6H.AGMo";
        String result = desc.encode("JQ", pass);
        
        assertEquals(expResult, result);
    }

    /**
     * Test of verify method, of class DEScrypt.
     * 一部AI生成
     */
    @Test
    public void testVerify() {
        System.out.println("verify");
        String[] ab = {"qwerty", "AaBEDDC6pJ05s",
        "password", "JQMuyS6H.AGMo",
        "hello","aaPwJ9XL9Y99E",
        "","aaQSqAReePlq6",
        "abc","zzsT4g5y.2SNE",
        "abcdefgh","zzcHgwjUppv8U",
        "12345678","ab1iBa.N.U2C6",
        "password","..UZoIyj/Hy/c",
        "U*U*U*U*","CCNf8Sbh3HDfQ",
        "U*U***U","CCX.K.MFy4Ois",
        "123456789","ab1iBa.N.U2C6",
        "abcdefgh","zzcHgwjUppv8U"
        };
        

        DEScrypt instance = new DEScrypt();
        boolean expResult = true;
        for (int i = 0; i < ab.length; i+= 2) {
            boolean result = instance.verify(ab[i], ab[i+1]);
            assertEquals(expResult, result, ab[i] + " " + ab[i+1]);
        }
        
    }
    
}
