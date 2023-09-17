package net.siisise.security.mac;

import java.util.Arrays;
import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * RFC っぽいテスト
 * NIST SP 800-38b
 */
public class CMACTest {
    
    public CMACTest() {
    }

    byte[] K        = Bin.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
    byte[] K1 = Bin.toByteArray("fbeed618357133667c85e08f7236a8de");
    byte[] K2 = Bin.toByteArray("f7ddac306ae266ccf90bc11ee46d513b");
    byte[] K192     = Bin.toByteArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b");
    byte[] K256     = Bin.toByteArray("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4");
    byte[] AES128K0 = Bin.toByteArray("7df76b0c1ab899b33e42f047b91b546f");
    byte[] M512  = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a"
                                 + "ae2d8a571e03ac9c9eb76fac45af8e51"
                                 + "30c81c46a35ce411e5fbc1191a0a52ef"
                                 + "f69f2445df4f9b17ad2b417be66c3710");

    /**
     * Test of init method, of class CMAC.
     */
    @Test
    public void testInit() {
        System.out.println("CMAC subkey Generation");
        byte[] Z = new byte[16];
        CMAC cmac = new CMAC();
        cmac.init(K);
        AES aes = new AES();
        aes.init(K);
        byte[] e = aes.encrypt(Z);
        assertArrayEquals(e, AES128K0);
        System.out.println("K:" + Bin.toHex(K));
        System.out.println("eZ:" + Bin.toHex(e));
        System.out.println("  K1:" + Bin.toHex(K1));
        System.out.println("c.K1:" + Bin.toHex(cmac.k1));
        System.out.println("  K2:" + Bin.toHex(K2));
        System.out.println("c.K2:" + Bin.toHex(cmac.k2));
        assertArrayEquals(cmac.k1, K1,"K1");
        assertArrayEquals(cmac.k2, K2,"K2");
    }

    /**
     * Test of update method, of class CMAC.
     * NIST AES-CMAC
     */
    @Test
    public void testExample1() {
        System.out.println("RFC 4493 Example 1: NIST SP 800-38b D.1 AES-128 Subkey Generation");
        byte[] CM = Bin.toByteArray("bb1d6929e95937287fa37d129b756746");
        CMAC cmac = new CMAC();
        cmac.init(K);
        assertArrayEquals(K1, cmac.k1);
        assertArrayEquals(K2, cmac.k2);
        System.out.println("NIST SP 800-38b Example 1:");
        byte[] M = new byte[0];
        byte[] H = cmac.doFinal(M);
        assertArrayEquals(CM,H);
    }

    /**
     * Example 2: len = 16
     * Test of update method, of class CMAC.
     */
    @Test
    public void testExample2() {
        System.out.println("RFC 4493 Example 2: len = 16 NIST SP 800-38b D.1 AES-128 Example 2");
        byte[] M  = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a");
        byte[] CM = Bin.toByteArray("070a16b46b4d4144f79bdd9dd04a287c");
        CMAC c = new CMAC();
        c.init(K);
        byte[] H = c.doFinal(M);
        assertArrayEquals(CM,H);
    }

    /**
     * Example 3: len = 40
     * Test of update method, of class CMAC.
     */
    @Test
    public void testExample3() {
        System.out.println("RFC 4493 Example 3: len = 40");
        byte[] M  = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51"
                + "30c81c46a35ce411");
        byte[] CM = Bin.toByteArray("dfa66747de9ae63030ca32611497c827");
        CMAC c = new CMAC();
        c.init(K);
        byte[] H = c.doFinal(M);
        assertArrayEquals(CM,H);
    }

    /**
     * Example 4: len = 40
     * Test of update method, of class CMAC.
     */
    @Test
    public void testExample4() {
        System.out.println("RFC 4493 Example 4: len = 64");
        byte[] CM = Bin.toByteArray("51f0bebf7e3b9d92fc49741779363cfe");
        CMAC c = new CMAC();
        c.init(K);
        byte[] H = c.doFinal(M512);
        assertArrayEquals(CM,H);
    }

    /**
     * NIST SP 800-38b D.2 AES-192
     * Example 5: len = 32040
     * Test of update method, of class CMAC.
     */
    @Test
    public void testExampleD2AES192() {
        System.out.println("NIST SP 800-38b D.2 AES-192");
        byte[] K1 = Bin.toByteArray("448a5b1c93514b273ee6439dd4daa296");
        byte[] K2 = Bin.toByteArray("8914b63926a2964e7dcc873ba9b5452c");
        byte[] T0 = Bin.toByteArray("d17ddf46adaacde531cac483de7a9367");
        byte[] T128 = Bin.toByteArray("9e99a7bf31e710900662f65e617c5184");
        byte[] T320 = Bin.toByteArray("8a1de5be2eb31aad089a82e6ee908b0e");
        byte[] T512 = Bin.toByteArray("a1d5df0eed790f794d77589659f39a11");
        CMAC cmac = new CMAC();
        cmac.init(K192);
        assertArrayEquals(K1, cmac.k1);
        assertArrayEquals(K2, cmac.k2);
        byte[] M = new byte[0];
        byte[] H = cmac.doFinal(M);
        assertArrayEquals(T0,H);
        M = Arrays.copyOf(M512, 16);
        H = cmac.doFinal(M);
        assertArrayEquals(T128, H);
        M = Arrays.copyOf(M512, 40);
        H = cmac.doFinal(M);
        assertArrayEquals(T320, H);
//        M = Arrays.copyOf(M512, 40);
        H = cmac.doFinal(M512);
        assertArrayEquals(T512, H);
    }


    /**
     * NIST SP 800-38b D.3 AES-256
     * Test of update method, of class CMAC.
     */
    @Test
    public void testExampleD3AES256() {
        System.out.println("NIST SP 800-38b D.3 AES-256");
        byte[] K1 = Bin.toByteArray("cad1ed03299eedac2e9a99808621502f");
        byte[] K2 = Bin.toByteArray("95a3da06533ddb585d3533010c42a0d9");
        byte[] T0 = Bin.toByteArray("028962f61b7bf89efc6b551f4667d983");
        byte[] T128 = Bin.toByteArray("28a7023f452e8f82bd4bf28d8c37c35c");
        byte[] T320 = Bin.toByteArray("aaf3d8f1de5640c232f5b169b9c911e6");
        byte[] T512 = Bin.toByteArray("e1992190549f6ed5696a2c056c315410");
        CMAC cmac = new CMAC();
        cmac.init(K256);
        assertArrayEquals(K1, cmac.k1);
        assertArrayEquals(K2, cmac.k2);
        byte[] M = new byte[0];
        byte[] H = cmac.doFinal(M);
        assertArrayEquals(T0,H);
        M = Arrays.copyOf(M512, 16);
        H = cmac.doFinal(M);
        assertArrayEquals(T128, H);
        M = Arrays.copyOf(M512, 40);
        H = cmac.doFinal(M);
        assertArrayEquals(T320, H);
//        M = Arrays.copyOf(M512, 40);
        H = cmac.doFinal(M512);
        assertArrayEquals(T512, H);
    }

    /**
     * Test of initk method, of class OMAC1.
     * http://www.nuee.nagoya-u.ac.jp/labs/tiwata/omac/tv/omac1-tv.txt
     */
    @Test
    public void testIwata() {
        System.out.println("OMAC1 Test Vectors");
//        byte[] L = Bin.toByteArray("7df76b0c1ab899b33e42f047b91b546f");
        byte[] Lu = Bin.toByteArray("fbeed618357133667c85e08f7236a8de");
        byte[] Lu2 = Bin.toByteArray("f7ddac306ae266ccf90bc11ee46d513b");
        System.out.println(" empty");
        byte[] Key = Bin.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] InE = Bin.toByteArray("77ddac306ae266ccf90bc11ee46d513b");
        byte[] exTag = Bin.toByteArray("bb1d6929e95937287fa37d129b756746");
//        GF gf = new GF(128, GF.FF128);
        CMAC omac = new CMAC();
        omac.init(Key);
        System.out.println("Key: " + Bin.toHex(Key));
        System.out.println("k1 : " + Bin.toHex(omac.k1));
        assertArrayEquals(Lu,omac.k1);
        System.out.println(Bin.toHex(omac.k2));
        assertArrayEquals(Lu2,omac.k2);
        byte[] T = omac.doFinal();
        assertArrayEquals(exTag, T);
        System.out.println(" 16-byte string");
        //Key = Bin.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] Msg = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a");
        exTag = Bin.toByteArray("070a16b46b4d4144f79bdd9dd04a287c");
        T = omac.doFinal(Msg);
        assertArrayEquals(exTag, T);
    }
}
