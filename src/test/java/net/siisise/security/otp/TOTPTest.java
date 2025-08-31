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
package net.siisise.security.otp;

import java.net.URI;
import java.net.URISyntaxException;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * TOTP Test.
 * 
 */
public class TOTPTest {
    
    public TOTPTest() {
    }

    /**
     * Test of generateOTP method, of class TOTP.
     */
    @Test
    public void testGenerateOTP() {
        System.out.println("generateOTP");
        byte[] secret = "12345678901234567890".getBytes();
        TOTP instance = new TOTP(); // SHA1
        instance.setSecret(secret);
        instance.setDigit(8);
        String expResult = "07081804";
        String result = instance.generateOTP(0x23523ec);
        assertEquals(expResult, result);
        expResult = "14050471";
        result = instance.generateOTP(0x23523ed);
        assertEquals(expResult, result);
        expResult = "89005924";
        result = instance.generateOTP(0x273ef07);
        assertEquals(expResult, result);

        String accountname = "abc@example.jp";
        String issuer = "組織 7%";
        URI uri = instance.generateKeyURI( accountname, issuer);
        expResult = "otpauth://totp/%E7%B5%84%E7%B9%94%207%25:abc@example.jp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=%E7%B5%84%E7%B9%94%207%25&digits=8";
        System.out.println(expResult);
        System.out.println(uri.toASCIIString());
        assertEquals(expResult, uri.toASCIIString());
    }

    /**
     * Test of generateOTP method, of class TOTP.
     */
    @Test
    public void testGenerateOTPSHA256() {
        System.out.println("generateOTP SHA-256");
        byte[] secret = "12345678901234567890123456789012".getBytes();
        long counter = 0x23523ec;
        TOTP instance = new TOTP("SHA256");
        instance.setSecret(secret);
        instance.setDigit(8);
        String expResult = "68084774";
        String result = instance.generateOTP(counter);
        assertEquals(expResult, result);
        expResult = "67062674";
        result = instance.generateOTP(0x23523ed);
        assertEquals(expResult, result);
        expResult = "91819424";
        result = instance.generateOTP(0x273ef07);
        assertEquals(expResult, result);
    }

    /**
     * Test of generateOTP method, of class TOTP.
     */
    @Test
    public void testGenerateOTPSHA512() {
        System.out.println("generateOTP SHA-512");
        byte[] secret = "1234567890123456789012345678901234567890123456789012345678901234".getBytes();
        long counter = 0x23523ec;
        TOTP instance = new TOTP("SHA512");
        instance.setSecret(secret);
        instance.setDigit(8);
        String expResult = "25091201";
        String result = instance.generateOTP(counter);
        assertEquals(expResult, result);
        expResult = "99943326";
        result = instance.generateOTP(0x23523ed);
        assertEquals(expResult, result);
        expResult = "93441116";
        result = instance.generateOTP(0x273ef07);
        assertEquals(expResult, result);
    }

    /**
     * Test of generateKeyURI method, of class TOTP.
     */
    @Test
    public void testGenerateKeyURI() {
        System.out.println("generateKeyURI");
        byte[] secret = "12345678901234567890123456789012".getBytes();
        String accountname = "abc@example.jp";
        String issuer = "SiisiseNet";
        String algorithm = "SHA256";
        TOTP instance = new TOTP();
        String exURI = "otpauth://totp/SiisiseNet:abc@example.jp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=SiisiseNet&algorithm=SHA256&digits=8";
        System.out.println(exURI);
        URI expResult;
        try {
            expResult = new URI(exURI);
        } catch (URISyntaxException ex) {
            throw new IllegalStateException(ex);
        }
        URI result = instance.generateKeyURI(secret, accountname, issuer, algorithm, 8, 30);
        System.out.println(result.toASCIIString());
        assertEquals(exURI, result.toASCIIString());
    }
    
    /**
     * Test of generateKeyURI method, of class TOTP.
     */
    @Test
    public void testParseKeyURI() throws URISyntaxException {
        System.out.println("parseKeyURI");
        byte[] secret = "12345678901234567890123456789012".getBytes();
        String accountname = "abc@example.jp";
        String issuer = "SiisiseNet";
        String algorithm = "SHA256";
        TOTP instance = new TOTP();
        String exURI = "otpauth://totp/SiisiseNet:abc@example.jp?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA&issuer=SiisiseNet&algorithm=SHA256&digits=8";
        System.out.println(exURI);
        instance.init(new URI(exURI));
        URI expResult;
        expResult = new URI(exURI);
        URI result = instance.generateKeyURI(secret, accountname, issuer, algorithm, 8, 30);
        System.out.println(result.toASCIIString());
        assertEquals(exURI, result.toASCIIString());
    }
}
