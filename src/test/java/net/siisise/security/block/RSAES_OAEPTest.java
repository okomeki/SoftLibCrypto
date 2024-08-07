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
package net.siisise.security.block;

import java.security.NoSuchAlgorithmException;
import java.util.Random;
import net.siisise.security.digest.SHA1;
import net.siisise.security.key.RSAKeyGen;
import net.siisise.security.key.RSAPrivateCrtKey;
import net.siisise.security.key.RSAPublicKey;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class RSAES_OAEPTest {
    
    public RSAES_OAEPTest() {
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
    public void testSomeMethod() throws NoSuchAlgorithmException {
        
        RSAPrivateCrtKey key = RSAKeyGen.generatePrivateKey(1000);
        RSAPublicKey pub = key.getPublicKey();
        byte[] msg = new byte[80];
        Random rnd = new Random();
        rnd.nextBytes(msg);
        
        RSAES es = new RSAES_OAEP(new SHA1());
        byte[] encd = es.encrypt(pub, msg);
        es = new RSAES_OAEP(new SHA1());
        byte[] dec = es.decrypt(key, encd);
        assertArrayEquals(msg, dec);
    }
    
}
