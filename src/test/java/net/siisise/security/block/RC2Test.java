package net.siisise.security.block;

import net.siisise.io.FileIO;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 * RFC 
 * @author okome
 */
public class RC2Test {
    
    public RC2Test() {
    }

    @Test
    public void testEnc() {
        System.out.println("encrypt");
        byte[] key   = {0,0,0,0,0,0,0,0};
        byte[] plane = {0,0,0,0,0,0,0,0};
        byte[] ex = {(byte)0xeb,(byte)0xb7,0x73,(byte)0xf9, (byte)0x93,0x27,(byte)0x8e,(byte)0xff};
        RC2 rc2 = new RC2();
        rc2.init(key);
        byte[] e = rc2.encrypt(plane, 0);
//        FileIO.dump(ex);
//        FileIO.dump(e);
        assertArrayEquals(e, ex);
        byte[] d = rc2.decrypt(e, 0);
        assertArrayEquals(d, plane);

        key   = new byte[] {-1,-1,-1,-1,-1,-1,-1,-1};
        plane = new byte[] {-1,-1,-1,-1,-1,-1,-1,-1};
        ex = new byte[] {0x27,(byte)0x8b,0x27,(byte)0xe4, 0x2e,0x2f,0x0d,0x49};
        rc2 = new RC2();
        rc2.init(key);
        e = rc2.encrypt(plane, 0);
        assertArrayEquals(e, ex);
        // TODO review the generated test code and remove the default call to fail.
    }

    /**
     * Test of getBlockLength method, of class RC2.
     */
    @Test
    public void testGetBlockLength() {
        System.out.println("getBlockLength");
        RC2 instance = new RC2();
        int expResult = 64;
        int result = instance.getBlockLength();
        assertEquals(expResult, result);
    }

    /**
     * Test of encrypt method, of class RC2.
     */
/*
    @Test
    public void testEncrypt() {
        System.out.println("encrypt");
        byte[] src = null;
        int offset = 0;
        RC2 instance = new RC2();
        byte[] expResult = null;
        byte[] result = instance.encrypt(src, offset);
        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
*/
    /**
     * Test of decrypt method, of class RC2.
     */
/*
    @Test
    public void testDecrypt() {
        System.out.println("decrypt");
        byte[] src = null;
        int offset = 0;
        RC2 instance = new RC2();
        byte[] expResult = null;
        byte[] result = instance.decrypt(src, offset);
        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
        fail("The test case is a prototype.");
    }
*/    
}
