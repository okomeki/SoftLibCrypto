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
package net.siisise.ietf.pkcs8;

import net.siisise.io.PEM;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.security.key.RSAPrivateCrtKey;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class RFC5958Test {
    
    public RFC5958Test() {
    }

    /**
     * Test of getRFC5958EncryptedPrivateKeyInfoASN1 method, of class RFC5958.
     */
    @Test
    public void testGetRFC5958EncryptedPrivateKeyInfoASN1() throws Exception {
        System.out.println("getRFC5958EncryptedPrivateKeyInfoASN1");
        RSAPrivateCrtKey key = null;
        byte[] pass = null;
        RFC5958 instance = new RFC5958();
        SEQUENCE expResult = null;
//        SEQUENCE result = instance.getRFC5958EncryptedPrivateKeyInfoASN1(key, pass);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of decrypt method, of class RFC5958.
     */
    @Test
    public void testDecrypt() throws Exception {
        System.out.println("RFC5958 decode test");
        PEM pem = new PEM("ENCRYPTED PRIVATE KEY");
        byte[] src = (byte[]) pem.load("c:/home/pki/letsencrypt/siisise.net/siisise.p8e").get(null);
        byte[] pass = "enya1652".getBytes();
        RSAPrivateCrtKey expResult = null;
//        RSAPrivateCrtKey result = RFC5958.decrypt(src, pass);
//        b64.encode(pass)
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
    
}
