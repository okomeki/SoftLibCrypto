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
package net.siisise.security.sign;

import net.siisise.security.digest.SHA1;
import net.siisise.security.digest.SHA224;
import net.siisise.security.key.DSAKeyGen;
import net.siisise.security.key.DSAPrivateKey;
import net.siisise.security.key.DSAPublicKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class DSATest {
    
    public DSATest() {
    }

    /**
     * Test of sign method, of class DSASign.
     */
    @Test
    public void test1016Sign() {
        System.out.println("1016sign");
        DSAKeyGen gen = new DSAKeyGen();
        DSAPrivateKey prv = gen.gen(DSAKeyGen.LN1016);
        DSAPublicKey pub = prv.getPublicKey();
        byte[] msg = "Hello DSA".getBytes();

        DSA sinstance = new DSA(new SHA1());
        sinstance.init(prv);
        sinstance.update(msg);
        byte[] sign = sinstance.sign();

        DSA verifyer = new DSA(new SHA1());
        verifyer.init(pub);
        verifyer.update(msg);
        assertTrue(verifyer.verify(sign));
    }
    

    /**
     * Test of sign method, of class DSASign.
     */
    @Test
    public void test2022Sign() {
        System.out.println("2022sign");
        DSAKeyGen gen = new DSAKeyGen();
        DSAPrivateKey prv = gen.gen(DSAKeyGen.LN2022);
        DSAPublicKey pub = prv.getPublicKey();
        byte[] msg = "Hello DSA".getBytes();

        DSA sinstance = new DSA(new SHA224());
        sinstance.init(prv);
        sinstance.update(msg);
        byte[] sign = sinstance.sign();

        DSA verifyer = new DSA(new SHA224());
        verifyer.init(pub);
        verifyer.update(msg);
        assertTrue(verifyer.verify(sign));
    }
}
