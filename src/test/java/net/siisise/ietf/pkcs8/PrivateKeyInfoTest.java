/*
 * Copyright 2025 okome.
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

import java.security.NoSuchAlgorithmException;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.lang.Bin;
import net.siisise.security.key.RSAKeyGen;
import net.siisise.security.key.RSAPrivateCrtKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class PrivateKeyInfoTest {
    
    public PrivateKeyInfoTest() {
    }

    /**
     * Test of rebind method, of class PrivateKeyInfo.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testRebind() throws NoSuchAlgorithmException {
        System.out.println("rebind");
        RSAPrivateCrtKey rsakey = RSAKeyGen.generatePrivateKey(1024);
        PrivateKeyInfo instance = rsakey.getPKCS8PrivateKeyInfo();
        byte[] expResult = instance.encodeASN1().encodeAll();
        System.out.println(Bin.toHex(expResult));
        byte[] result = instance.rebind(new ASN1DERFormat());
        System.out.println(Bin.toHex(result));
        assertArrayEquals(expResult, result);
    }

    /**
     * Test of encodeASN1 method, of class PrivateKeyInfo.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testEncodeASN1() throws NoSuchAlgorithmException {
        System.out.println("encodeASN1");
        RSAPrivateCrtKey rsakey = RSAKeyGen.generatePrivateKey(1024);
        PrivateKeyInfo instance = rsakey.getPKCS8PrivateKeyInfo();
        ASN1Tag expResult = instance.rebind(new ASN1Convert());
        SEQUENCEMap result = instance.encodeASN1();
        assertEquals(expResult, result);
    }

    /**
     * Test of decode method, of class PrivateKeyInfo.
     * @throws java.security.NoSuchAlgorithmException
     */
    @Test
    public void testDecode() throws NoSuchAlgorithmException {
        System.out.println("decode");
        RSAPrivateCrtKey rsakey = RSAKeyGen.generatePrivateKey(1024);
        PrivateKeyInfo instance = rsakey.getPKCS8PrivateKeyInfo();
        SEQUENCE seq = instance.encodeASN1();
        PrivateKeyInfo expResult = instance;
        PrivateKeyInfo result = PrivateKeyInfo.decode(seq);
        assertEquals(expResult.encodeASN1(), result.encodeASN1());
    }
    
}
