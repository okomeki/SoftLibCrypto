package net.siisise.security.mac;

import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class CMACTest {
    
    public CMACTest() {
    }

    byte[] K        = Bin.toByteArray("2b7e151628aed2a6abf7158809cf4f3c");
    byte[] AES128K0 = Bin.toByteArray("7df76b0c1ab899b33e42f047b91b546f");
//    byte[] K1       = Bin.toByteArray("fbeed618357133667c85e08f7236a8de");
//    byte[] K2       = Bin.toByteArray("f7ddac306ae266ccf90bc11ee46d513b");

    /**
     * Test of init method, of class CMAC.
     */
    @Test
    public void testInit() {
        System.out.println("CMAC subkey Generation");
        byte[] Z = new byte[16];
        CMAC c = new CMAC();
        c.init(K);
        AES a1 = new AES();
        a1.init(K);
        byte[] e = a1.encrypt(Z);
        assertArrayEquals(e, AES128K0);
        System.out.println("K:" + Bin.toHex(K));
        System.out.println("eZ:" + Bin.toHex(e));
//        System.out.println("  K1:" + Bin.toHex(K1));
//        System.out.println("c.K1:" + Bin.toHex(c.k1));
//        System.out.println("  K2:" + Bin.toHex(K2));
//        System.out.println("c.K2:" + Bin.toHex(c.k2));
//        assertArrayEquals(c.k1, K1,"K1");
//        assertArrayEquals(c.k2, K2,"K2");
    }

    /**
     * Test of update method, of class CMAC.
     */
    @Test
    public void testExample1() {
        System.out.println("Example 1:");
        byte[] CM = Bin.toByteArray("bb1d6929e95937287fa37d129b756746");
        CMAC c = new CMAC();
        c.init(K);
        byte[] M = new byte[0];
        byte[] H = c.doFinal(M);
        assertArrayEquals(CM,H);
    }

    /**
     * Example 2: len = 16
     * Test of update method, of class CMAC.
     */
    @Test
    public void testExample2() {
        System.out.println("Example 2: len = 16");
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
        System.out.println("Example 3: len = 40");
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
        System.out.println("Example 4: len = 64");
        byte[] M  = Bin.toByteArray("6bc1bee22e409f96e93d7e117393172a"
                + "ae2d8a571e03ac9c9eb76fac45af8e51"
                + "30c81c46a35ce411e5fbc1191a0a52ef"
                + "f69f2445df4f9b17ad2b417be66c3710");
        byte[] CM = Bin.toByteArray("51f0bebf7e3b9d92fc49741779363cfe");
        CMAC c = new CMAC();
        c.init(K);
        byte[] H = c.doFinal(M);
        assertArrayEquals(CM,H);
    }
}
