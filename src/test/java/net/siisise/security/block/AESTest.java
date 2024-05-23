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
package net.siisise.security.block;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import net.siisise.lang.Bin;
import net.siisise.security.mode.CBC;
import net.siisise.security.mode.CTR;
import net.siisise.security.mode.ECB;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class AESTest {
    
    public AESTest() {
    }

    /**
     * Test of getBlockLength method, of class AESCBC.
     */
    @Test
    public void testGetBlockLength() {
        System.out.println("getBlockLength");
        AESLong instance = new AESLong();
        int expResult = 0;
        int result = instance.getBlockLength();
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    @Test
    public void testSbox() {
        System.out.println("FIPS 197 Appendix B - Cipher Example");
        byte[] key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, 0x15, (byte)0x88, 0x09, (byte)0xcf, 0x4f, 0x3c };
        byte[] iv = new byte[16];
        Block aes = new CBC(new AES());
        aes.init(key,iv);
//        for ( int i = 0; i < 24; i++ ) {
//            System.out.println("w["+i+"] " + Integer.toHexString(aes.w[i]) );
//        }
//        for ( int i = 0; i < aes.rcon.length; i++) {
//            System.out.println(Integer.toHexString(aes.rcon[i]));
//        }
        
        byte[] input = {
            0x32,0x43,(byte)0xf6,(byte)0xa8,(byte)0x88,0x5a,0x30,(byte)0x8d,
            0x31,0x31,(byte)0x98,(byte)0xa2,(byte)0xe0,0x37,0x07,0x34};
        byte[] output = aes.encrypt(input, 0);
        aes.init(key,iv);
        byte[] x = aes.decrypt(output, 0);
        for ( int i = 0; i < x.length; i++) {
//            System.out.println("in:" + input[i] + " out:" + x[i]);
            assertArrayEquals(x, input);
        }
        
    }

    @Test
    public void testFips197AppendixB() {
        System.out.println("FIPS 197 Appendix B - Cipher Example");
        byte[] key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
            (byte)0xab, (byte)0xf7, 0x15, (byte)0x88, 0x09, (byte)0xcf, 0x4f, 0x3c };
        Block aes = new AES();
        aes.init(key);
        
        byte[] input = {
            0x32,0x43,(byte)0xf6,(byte)0xa8,(byte)0x88,0x5a,0x30,(byte)0x8d,
            0x31,0x31,(byte)0x98,(byte)0xa2,(byte)0xe0,0x37,0x07,0x34};
        byte[] expResult = {0x39,0x25,(byte)0x84,0x1d,0x02,(byte)0xdc,0x09,(byte)0xfb,
        (byte)0xdc,0x11,(byte)0x85,(byte)0x97,0x19,0x6a,0x0b,0x32};

        // 暗号化
        byte[] encoded = aes.encrypt(input, 0);
        assertArrayEquals(encoded,expResult);
        
        // デコード
        aes.init(key);
        byte[] decoded = aes.decrypt(encoded, 0);
        assertArrayEquals(decoded, input);
        
    }

    @Test
    public void testFips197AppendixC() {
        System.out.println("FIPS 197 Appendix C - Example Vectors");
        byte[] key = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };
        Block aes = new AES();
        aes.init(key);

        
        byte[] input = {
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            (byte)0x88,(byte)0x99,(byte)0xaa,(byte)0xbb,(byte)0xcc,(byte)0xdd,(byte)0xee,(byte)0xff};
        byte[] expResult = {0x69,(byte)0xc4,(byte)0xe0,(byte)0xd8,(byte)0x6a,(byte)0x7b,(byte)0x04,(byte)0x30,
            (byte)0xd8,(byte)0xcd,(byte)0xb7,(byte)0x80,(byte)0x70,(byte)0xb4,(byte)0xc5,(byte)0x5a};

        // 暗号化
        byte[] encoded = aes.encrypt(input, 0);
        assertArrayEquals(encoded,expResult);
        
        // デコード
        aes.init(key);
        byte[] decoded = aes.decrypt(encoded, 0);
        assertArrayEquals(decoded, input);
        
    }

    @Test
    public void testRFC3602Test1() {
        System.out.println("RFC 3602 AES CBC 4.Test #1");
        byte[] key = { 0x06,(byte)0xa9,0x21,0x40,0x36,(byte)0xb8,(byte)0xa1,0x5b,
            0x51,0x2e,0x03,(byte)0xd5,0x34,0x12,0x00,0x06 };
        byte[] iv = {0x3d,(byte)0xaf,(byte)0xba,0x42,(byte)0x9d,(byte)0x9e,(byte)0xb4,0x30,
            (byte)0xb4,0x22,(byte)0xda,(byte)0x80,0x2c,(byte)0x9f,(byte)0xac,0x41};

        Block aes = new CBC(new AES());
        aes.init(key,iv);
        
        byte[] input = "Single block msg".getBytes();
        byte[] expResult = {(byte)0xe3,(byte)0x53,(byte)0x77,(byte)0x9c,(byte)0x10,(byte)0x79,(byte)0xae,(byte)0xb8,(byte)0x27,(byte)0x08,(byte)0x94,(byte)0x2d,(byte)0xbe,(byte)0x77,(byte)0x18,(byte)0x1a};

        // 暗号化
        byte[] encoded = aes.encrypt(input, 0, input.length);
        assertArrayEquals(encoded,expResult);
        
        // デコード
        aes.init(key,iv);
        byte[] decoded = aes.decrypt(encoded, 0, encoded.length);
        assertArrayEquals(decoded, input);
        
    }

    @Test
    public void testRFC3602Test2() {
        System.out.println("RFC 3602 AES CBC 4.Test #2");
        byte[] key = {
            (byte)0xc2,(byte)0x86,(byte)0x69,(byte)0x6d,(byte)0x88,(byte)0x7c,(byte)0x9a,(byte)0xa0,
            (byte)0x61,(byte)0x1b,(byte)0xbb,(byte)0x3e,(byte)0x20,(byte)0x25,(byte)0xa4,(byte)0x5a};
        byte[] iv = {
            (byte)0x56,(byte)0x2e,(byte)0x17,(byte)0x99,(byte)0x6d,(byte)0x09,(byte)0x3d,(byte)0x28,
            (byte)0xdd,(byte)0xb3,(byte)0xba,(byte)0x69,(byte)0x5a,(byte)0x2e,(byte)0x6f,(byte)0x58};

        CBC aes = new CBC(new AES());
        aes.init(key,iv);
        
        byte[] input = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
        byte[] expResult = {
            (byte)0xd2,(byte)0x96,(byte)0xcd,(byte)0x94,(byte)0xc2,(byte)0xcc,(byte)0xcf,(byte)0x8a,
            (byte)0x3a,(byte)0x86,(byte)0x30,(byte)0x28,(byte)0xb5,(byte)0xe1,(byte)0xdc,(byte)0x0a,
            (byte)0x75,(byte)0x86,(byte)0x60,(byte)0x2d,(byte)0x25,(byte)0x3c,(byte)0xff,(byte)0xf9,
            (byte)0x1b,(byte)0x82,(byte)0x66,(byte)0xbe,(byte)0xa6,(byte)0xd6,(byte)0x1a,(byte)0xb1};

        // 暗号化
        byte[] encoded = aes.encrypt(input, 0, input.length);
        assertArrayEquals(encoded,expResult);
        
        // デコード
        aes.init(key,iv);
        byte[] decoded = aes.decrypt(encoded, 0, input.length);
        assertArrayEquals(decoded, input);
        
    }

    /**
     * Test of init method, of class AESCBC.
     */
    @Test
    public void testInit() {
        System.out.println("init");
        byte[] key = null;
        Block instance = new AES();
//        instance.init(key);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of encrypt method, of class AESCBC.
     * @throws java.security.InvalidAlgorithmParameterException
     */
    @Test
    public void testEncrypt() throws InvalidAlgorithmParameterException {
        System.out.println("encrypt speed test");
        String alg = "AES/CTR";
        //EncodeOutputStream encout = new EncodeOutputStream(instance,);
//        byte[] expResult = null;
//        byte[] key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
//            (byte)0xab, (byte)0xf7, 0x15, (byte)0x88, 0x09, (byte)0xcf, 0x4f, 0x3c };
//        byte[] key = { 0x2b, 0x7e, 0x15, 0x16, 0x28, (byte)0xae, (byte)0xd2, (byte)0xa6,
//            (byte)0xab, (byte)0xf7, 0x15, (byte)0x88, 0x09, (byte)0xcf, 0x4f, 0x3c };
        byte[] key = {
            (byte)0xc2,(byte)0x86,(byte)0x69,(byte)0x6d,(byte)0x88,(byte)0x7c,(byte)0x9a,(byte)0xa0,
            (byte)0x61,(byte)0x1b,(byte)0xbb,(byte)0x3e,(byte)0x20,(byte)0x25,(byte)0xa4,(byte)0x5a};
        byte[] iv = {
            (byte)0x56,(byte)0x2e,(byte)0x17,(byte)0x99,(byte)0x6d,(byte)0x09,(byte)0x3d,(byte)0x28,
            (byte)0xdd,(byte)0xb3,(byte)0xba,(byte)0x69,(byte)0x5a,(byte)0x2e,(byte)0x6f,(byte)0x58};
/*
        byte[] input = {
            0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
            0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f };
        byte[] expResult = {
            (byte)0xd2,(byte)0x96,(byte)0xcd,(byte)0x94,(byte)0xc2,(byte)0xcc,(byte)0xcf,(byte)0x8a,
            (byte)0x3a,(byte)0x86,(byte)0x30,(byte)0x28,(byte)0xb5,(byte)0xe1,(byte)0xdc,(byte)0x0a,
            (byte)0x75,(byte)0x86,(byte)0x60,(byte)0x2d,(byte)0x25,(byte)0x3c,(byte)0xff,(byte)0xf9,
            (byte)0x1b,(byte)0x82,(byte)0x66,(byte)0xbe,(byte)0xa6,(byte)0xd6,(byte)0x1a,(byte)0xb1};
*/
/*        
        byte[] input = {
            0x32,0x43,(byte)0xf6,(byte)0xa8,(byte)0x88,0x5a,0x30,(byte)0x8d,
            0x31,0x31,(byte)0x98,(byte)0xa2,(byte)0xe0,0x37,0x07,0x34};
        byte[] expResult = {0x39,0x25,(byte)0x84,0x1d,0x02,(byte)0xdc,0x09,(byte)0xfb,
        (byte)0xdc,0x11,(byte)0x85,(byte)0x97,0x19,0x6a,0x0b,0x32};
*/        
        int size = 500;
        byte[] src;
        byte[] encd = null;// = instance.encrypt(src, 0, size*1024*1024);
        src = SecureRandom.getSeed(size * 1024 * 1024);
        for ( int loop = 0; loop < 4; loop++ ) {
            //src = input; //new byte[size*1024 * 1024];
            //src = input;
            //int[] intSrc = new int[src.length/4];
            //IntBlock.btoi(src,0,intSrc,src.length/4);
        
    //        Block instance = new AES();
            long d = System.nanoTime();
            Block instance = new CTR(new AES());
            instance.init(key,iv);
            //intEncd = instance.encrypt(intSrc, 0, intSrc.length);
            encd = instance.encrypt(src, 0, src.length);
        
            long e = System.nanoTime();

            long t = e - d;
            System.out.println( "SoftLibCrypto " + alg + " encrypt time : "  + t );
        
            System.out.println( " speed : " + (size * 8*1024 / (t/1000/1000)) + "Mbps?" );
            //assertArrayEquals(encd,expResult);

            d = System.nanoTime();
            instance.init(key,iv);
            byte[] plane2 = instance.decrypt(encd, 0, src.length);
            e = System.nanoTime();
        
            assertArrayEquals(src, plane2,"戻ってない");
        
            //encd = IntBlock.itob(intEncd);
            t = e - d;
            System.out.println("SoftLibCrypto " + alg + " decrypt time : "  + t );
        
            System.out.println( " speed : " + (size * 8*1024 / (t/1000/1000)) );
        }
        String ALG = alg + "/nopadding";

        try {
//            byte[] plane2;
            long d = System.nanoTime();
            SecretKeySpec keysp = new SecretKeySpec(key, "AES");
            IvParameterSpec cbciv = new IvParameterSpec(iv);
            Cipher aescbc = Cipher.getInstance(ALG);
            // ivを省略するとランダムになってしまうん?
            aescbc.init(Cipher.ENCRYPT_MODE, keysp, cbciv );
//            aescbc.init(Cipher.ENCRYPT_MODE, keysp );
            
            byte[] plane2 = aescbc.doFinal(src);
            long e = System.nanoTime();
            
//            for ( int i =0; i < 16; i++) {
//                System.out.println(Integer.toHexString(encd[i]) + " " + Integer.toHexString(plane2[i]));
//            }
            
            assertArrayEquals(encd, plane2,"CBCがちがうのか");
            long t = e - d;
            System.out.println( "Java JDK OpenSSL CPU AES-NI? encrypt time : "  + t );
            
            System.out.println( " speed : " + (size * 8*1024 / (t/1000/1000)) + "Mbps?" );

            d = System.nanoTime();
            aescbc.init(Cipher.DECRYPT_MODE, keysp, cbciv );
            encd = aescbc.doFinal(plane2);
            e = System.nanoTime();
            
            assertArrayEquals(src, encd,"JDK dec CBCがちがうのか");
            t = e - d;
            System.out.println( "Java JDK OpenSSL CPU AES-NI? decrypt time : "  + t );

            System.out.println( " speed : " + (size * 8*1024 / (t/1000/1000)) + "Mbps?" );

//        byte[] result = instance.encrypt(in, offset);
//        assertArrayEquals(expResult, result);
// TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(AESTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchPaddingException ex) {
            Logger.getLogger(AESTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(AESTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(AESTest.class.getName()).log(Level.SEVERE, null, ex);
        } catch (BadPaddingException ex) {
            Logger.getLogger(AESTest.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    /**
     * Test of decrypt method, of class AESCBC.
     */
    @Test
    public void testDecrypt() {
        System.out.println("decrypt");
        byte[] src = null;
        int offset = 0;
//        AESCBC instance = new AESCBC();
        byte[] expResult = null;
//        byte[] result = instance.decrypt(src, offset);
//        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * NIST SP 800-38A Appendix F.
     * 
     */
    @Test
    public void test800_38A_F1_1() {
        System.out.println("NIST SP 800-38A F.1.1");
        byte[] key = Bin.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] plain = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a");
        byte[] cipher = Bin.toByteArray("3ad77bb40d7a3660a89ecaf32466ef97");
        ECB aes = new ECB(new AES());
        aes.init(key);
        byte[] result = aes.encrypt(plain);
        assertArrayEquals(cipher, result);

        plain = Bin.toByteArray("ae2d8a571e03ac9c9eb76fac45af8e51");
        cipher = Bin.toByteArray("f5d3d58503b9699de785895a96fdbaaf");
        result = aes.encrypt(plain);
        assertArrayEquals(cipher, result);

        plain = Bin.toByteArray("30c81c46a35ce411e5fbc1191a0a52ef");
        cipher = Bin.toByteArray("43b1cd7f598ece23881b00e3ed030688");
        result = aes.encrypt(plain);
        assertArrayEquals(cipher, result);

        plain = Bin.toByteArray("f69f2445df4f9b17ad2b417be66c3710");
        cipher = Bin.toByteArray("7b0c785e27e8ad3f8223207104725dd4");
        result = aes.encrypt(plain);
        assertArrayEquals(cipher, result);
    }
    
    /**
     * NIST SP 800-38A Appendix F.
     * 
     */
    @Test
    public void test800_38A_F1_2() {
        System.out.println("NIST SP 800-38A F.1.2");
        byte[] key = Bin.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] plain = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a");
        byte[] cipher = Bin.toByteArray("3ad77bb40d7a3660a89ecaf32466ef97");
        ECB aes = new ECB(new AES());
        aes.init(key);
        byte[] result = aes.decrypt(cipher);
        assertArrayEquals(plain, result);

        plain = Bin.toByteArray("ae2d8a571e03ac9c9eb76fac45af8e51");
        cipher = Bin.toByteArray("f5d3d58503b9699de785895a96fdbaaf");
        result = aes.decrypt(cipher);
        assertArrayEquals(plain, result);

        plain = Bin.toByteArray("30c81c46a35ce411e5fbc1191a0a52ef");
        cipher = Bin.toByteArray("43b1cd7f598ece23881b00e3ed030688");
        result = aes.decrypt(cipher);
        assertArrayEquals(plain, result);

        plain = Bin.toByteArray("f69f2445df4f9b17ad2b417be66c3710");
        cipher = Bin.toByteArray("7b0c785e27e8ad3f8223207104725dd4");
        result = aes.decrypt(cipher);
        assertArrayEquals(plain, result);
    }

    /**
     * NIST SP 800-38A Appendix F.
     * 
     */
    @Test
    public void test800_38A_F1_3() {
        System.out.println("NIST SP 800-38A F.1.3");
        byte[] key = Bin.toByteArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
        byte[] plain = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a");
        byte[] cipher = Bin.toByteArray("bd334f1d6e45f25ff712a214571fa5cc");
        ECB aes = new ECB(new AES());
        aes.init(key);
        byte[] result = aes.encrypt(plain);
        assertArrayEquals(cipher, result);

        plain = Bin.toByteArray("ae2d8a571e03ac9c9eb76fac45af8e51");
        cipher = Bin.toByteArray("974104846d0ad3ad7734ecb3ecee4eef");
        result = aes.encrypt(plain);
        assertArrayEquals(cipher, result);

        plain = Bin.toByteArray("30c81c46a35ce411e5fbc1191a0a52ef");
        cipher = Bin.toByteArray("ef7afd2270e2e60adce0ba2face6444e");
        result = aes.encrypt(plain);
        assertArrayEquals(cipher, result);

        plain = Bin.toByteArray("f69f2445df4f9b17ad2b417be66c3710");
        cipher = Bin.toByteArray("9a4b41ba738d6c72fb16691603c18e0e");
        result = aes.encrypt(plain);
        assertArrayEquals(cipher, result);
    }
}
