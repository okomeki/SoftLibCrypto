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
import net.siisise.security.mode.CBC;
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
        String alg = "AES/CBC";
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
        //src = input; //new byte[size*1024 * 1024];
        src = SecureRandom.getSeed(size * 1024 * 1024);
        //src = input;
        //int[] intSrc = new int[src.length/4];
        //IntBlock.btoi(src,0,intSrc,src.length/4);
        
        byte[] encd;// = instance.encrypt(src, 0, size*1024*1024);
//        Block instance = new AES();
        long d = System.nanoTime();
        Block instance = new CBC(new AES());
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
//        System.out.println("encdl " + encd.length);
        byte[] plane2 = instance.decrypt(encd, 0, src.length);
//        int[] plane4 = instance.decrypt(intEncd, 0, intSrc.length);
        e = System.nanoTime();
        
        assertArrayEquals(src, plane2,"戻ってない");
//        assertArrayEquals(intSrc, plane4,"戻ってない");
        
        //encd = IntBlock.itob(intEncd);
        t = e - d;
        System.out.println("SoftLibCrypto " + alg + " decrypt time : "  + t );
        
        System.out.println( " speed : " + (size * 8*1024 / (t/1000/1000)) );
        
        String ALG = alg + "/nopadding";

        try {
//            byte[] plane2;
            d = System.nanoTime();
            SecretKeySpec keysp = new SecretKeySpec(key, "AES");
            IvParameterSpec cbciv = new IvParameterSpec(iv);
            Cipher aescbc = Cipher.getInstance(ALG);
            // ivを省略するとランダムになってしまうん?
            aescbc.init(Cipher.ENCRYPT_MODE, keysp, cbciv );
//            aescbc.init(Cipher.ENCRYPT_MODE, keysp );
            
            plane2 = aescbc.doFinal(src);
            e = System.nanoTime();
            
//            for ( int i =0; i < 16; i++) {
//                System.out.println(Integer.toHexString(encd[i]) + " " + Integer.toHexString(plane2[i]));
//            }
            
            assertArrayEquals(encd, plane2,"CBCがちがうのか");
            t = e - d;
            System.out.println( "Java JDK OpenSSL CPU AES-NI? encrypt time : "  + t );
            
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
    
}
