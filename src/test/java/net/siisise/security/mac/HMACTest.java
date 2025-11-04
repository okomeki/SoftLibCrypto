/*
 * Copyright 2023 Siisise Net.
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
package net.siisise.security.mac;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.SecretKeySpec;
import net.siisise.io.DumpOutputStream;
import net.siisise.lang.Bin;
import net.siisise.security.digest.MD5;
import net.siisise.security.digest.SHA1;
import net.siisise.security.digest.SHA224;
import net.siisise.security.digest.SHA256;
import net.siisise.security.digest.SHA3256;
import net.siisise.security.digest.SHA384;
import net.siisise.security.digest.SHA512;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 * RFC 2202 HMAC-MD5, HMAC-SHA-1 テスト
 * RFC 4231 HMAC-SHA-224, HMAC-SHA-256, HMAC-SHA-384, HMAC-SHA-512 テスト
 * RFC 4868
 * 
 * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/HMAC_SHA3-512.pdf
 */
public class HMACTest {

    public HMACTest() {
    }

    static byte[] toHex(String src) {
        return Bin.toByteArray(src);
    }

    public static void dump(byte[] src) {
        try {
            OutputStream o;
            o = new DumpOutputStream(new PrintWriter(System.out));
            o.write(src);
            o.flush();
            System.out.println();
        } catch (IOException ex) {
            Logger.getLogger(HMACTest.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    /**
     * Test of hmac method, of class HMAC.
     */
    @Test
    public void testHmacMD5() {
        System.out.println("hmac MD5");
        byte[] key;
        byte[] src;
        byte[] expResult;

        MessageDigest md = new MD5();
        key = toHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        src = "Hi There".getBytes();
        expResult = toHex("9294727a3638bb1c13f48ef8158bfc9d");
        HMAC instance = new HMAC(md, key);
        byte[] result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result,"HMAC-MD5:1");
//        Mac mac = new Mac(new HMACSpi(md));

        key = "Jefe".getBytes();
        src = "what do ya want for nothing?".getBytes();
        expResult = toHex("750c783e6ab0b503eaa86e310a5db738");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals( expResult, result,"HMAC-MD5:2");

        key = toHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        src = new byte[50];
        for (int i = 0; i < 50; i++) {
            src[i] = (byte) 0xdd;
        }
        expResult = toHex("56be34521d144c88dbb8c733f0e8b3f6");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-MD5:3");

        key = toHex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        src = new byte[50];
        for (int i = 0; i < 50; i++) {
            src[i] = (byte) 0xcd;
        }
        expResult = toHex("697eaf0aca3a3aea3a75164746ffaa79");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-MD5:4");

        key = toHex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
        src = "Test With Truncation".getBytes();
        expResult = toHex("56461ef2342edc00f9bab995690efd4c");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-MD5:5");

        key = new byte[80];
        for (int i = 0; i < 80; i++) {
            key[i] = (byte) 0xaa;
        }
        src = "Test Using Larger Than Block-Size Key - Hash Key First".getBytes();
        expResult = toHex("6b1ab7fe4bd7bf8f0b62e6ce61b9d0cd");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-MD5:6");

        src = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".getBytes();
        expResult = toHex("6f630fad67cda0ee1fb1f562db3aa53e");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-MD5:7");
    }

    /**
     * Test of hmac method, of class HMAC.
     */
    @Test
    public void testHmacSHA1() {
        System.out.println("hmac SHA1");
        byte[] key;
        byte[] src;

        MessageDigest md = new SHA1();
        key = toHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        src = "Hi There".getBytes();
        byte[] expResult = toHex("b617318655057264e28bc0b6fb378c8ef146be00");
        HMAC instance = new HMAC(md, key);
        byte[] result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA1:1");

        key = "Jefe".getBytes();
        src = "what do ya want for nothing?".getBytes();
        expResult = toHex("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA1:2");

        key = toHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        src = new byte[50];
        for (int i = 0; i < 50; i++) {
            src[i] = (byte) 0xdd;
        }
        expResult = toHex("125d7342b9ac11cd91a39af48aa17b4f63f175d3");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA1:3");

        key = toHex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        src = new byte[50];
        for (int i = 0; i < 50; i++) {
            src[i] = (byte) 0xcd;
        }
        expResult = toHex("4c9007f4026250c6bc8414f9bf50c86c2d7235da");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA1:4");

        key = toHex("0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c");
        src = "Test With Truncation".getBytes();
        expResult = toHex("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA1:5");

        key = new byte[80];
        for (int i = 0; i < 80; i++) {
            key[i] = (byte) 0xaa;
        }
        src = "Test Using Larger Than Block-Size Key - Hash Key First".getBytes();
        expResult = toHex("aa4ae5e15272d00e95705637ce8a3b55ed402112");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA1:6");

        src = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data".getBytes();
        expResult = toHex("e8e99d0f45237d786d6bbaa7965c7808bbff1a91");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA1:7");
    }

    /**
     * Test of hmac method, of class HMAC.
     */
    @Test
    public void testHmacSHA2() {
        System.out.println("hmac SHA2");
        byte[] key;
        byte[] src;
        byte[] result;
        byte[] expResult;

        MessageDigest md = new SHA224();
        key = toHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        src = "Hi There".getBytes();
        expResult = toHex("896fb1128abbdf196832107cd49df33f47b4b1169912ba4f53684b22");
        HMAC instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-224:1");

        SecretKeySpec skey = new SecretKeySpec(key,"HMAC-SHA-224");
        instance = new HMAC(skey);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-224:1");
        
        md = new SHA256();
        expResult = toHex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-256:1");

        md = new SHA384();
        expResult = toHex("afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6");
        instance = new HMAC(md, 1024, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-384:1");

        md = new SHA512();
        expResult = toHex("87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854");
        instance = new HMAC(md, 1024, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-512:1");

        key = toHex("4a656665");
        src = "what do ya want for nothing?".getBytes();

        md = new SHA224();
        expResult = toHex("a30e01098bc6dbbf45690f3a7e9e6d0f8bbea2a39e6148008fd05e44");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-224:2");

        md = new SHA256();
        expResult = toHex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-256:2");

        md = new SHA384();
        expResult = toHex("af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649");
        instance = new HMAC(md, 1024, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-384:2");

        md = new SHA512();
        expResult = toHex("164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737");
        instance = new HMAC(md, 1024, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-512:2");

        key = toHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        src = toHex("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd");

        md = new SHA224();
        expResult = toHex("7fb3cb3588c6c1f6ffa9694d7d6ad2649365b0c1f65d69d1ec8333ea");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-224:3");

        md = new SHA256();
        expResult = toHex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-256:3");

        md = new SHA384();
        expResult = toHex("88062608d3e6ad8a0aa2ace014c8a86f0aa635d947ac9febe83ef4e55966144b2a5ab39dc13814b94e3ab6e101a34f27");
        instance = new HMAC(md, 1024, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-384:3");

        md = new SHA512();
        expResult = toHex("fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb");
        instance = new HMAC(md, 1024, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-512:3");

        key = toHex("0102030405060708090a0b0c0d0e0f10111213141516171819");
        src = toHex("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd");

        md = new SHA224();
        expResult = toHex("6c11506874013cac6a2abc1bb382627cec6a90d86efc012de7afec5a");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-224:4");

        md = new SHA256();
        expResult = toHex("82558a389a443c0ea4cc819899f2083a85f0faa3e578f8077a2e3ff46729665b");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-256:4");

        md = new SHA384();
        expResult = toHex("3e8a69b7783c25851933ab6290af6ca77a9981480850009cc5577c6e1f573b4e6801dd23c4a7d679ccf8a386c674cffb");
        instance = new HMAC(md, 1024, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-384:4");

        md = new SHA512();
        expResult = toHex("b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3dba91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd");
        instance = new HMAC(md, 1024, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-512:4");
        
        key = "This is your secret".getBytes();
        src = "hoge".getBytes();
        md = new SHA256();
        expResult = toHex("4a7bc6c59ebc1a83dc38ec4fd537f98994a9210bf09ad9fc8c60c2ae83746d82");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA-256:おまけ");
    }

    /**
     * Test of hmac method, of class HMAC.
     */
    @Test
    public void testHmacSHA3() {
        System.out.println("hmac SHA3");
        byte[] key;
        byte[] src;
        byte[] result;
        byte[] expResult;

        MessageDigest md = new SHA3256();
        key = toHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        src = "Sample message for keylen<blocklen".getBytes();
        expResult = toHex("4fe8e202c4f058e8dddc23d8c34e467343e23555e24fc2f025d598f558f67205");
        HMAC instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA3-256:1");

        key = toHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f8081828384858687");
        src = "Sample message for keylen=blocklen".getBytes();
        expResult = toHex("68b94e2e538a9be4103bebb5aa016d47961d4d1aa906061313b557f8af2c3faa");
        instance = new HMAC(md, key);
        result = instance.doFinal(src);
        dump(result);
        assertArrayEquals(expResult, result, "HMAC-SHA3-256:1");
    }
}
