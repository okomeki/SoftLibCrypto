package net.siisise.security.mode;

import net.siisise.lang.Bin;
import net.siisise.security.block.AES;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * NIST のテストとかある.
 * 
 */
public class GCMTest {
    
    public GCMTest() {
    }

    /**
     * Test of getBlockLength method, of class GCM.
     */
    @Test
    public void testGetBlockLength() {
        System.out.println("getBlockLength");
        GCM gcm = new GCM();
        int expResult = 128;
        int result = gcm.getBlockLength();
        assertEquals(expResult, result);
    }

    /**
     * Test of init method, of class GCM.
     */
    @Test
    public void testInit() {
        System.out.println("init");
        byte[][] params = null;
        GCM gcm = new GCM();
        gcm.init(new byte[16], new byte[16]);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
    
    /**
     * NIST 
     * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
     */
    @Test
    public void testAES_GCM() {
        System.out.println("GCM-AES128 Example #1");
        byte[] K = Bin.toByteArray("FEFFE9928665731C6D6A8F9467308308");
        byte[] IV = Bin.toByteArray("CAFEBABEFACEDBADDECAF8888");
        
        
    }
    
    /*
     * NIST GCM Test Vectors (SP 800-38D)
     */
/*
    @Test
    public void testNIST() throws IOException {
        System.out.println("NIST SP 800-38D");
        BufferedReader in = new BufferedReader(
                new InputStreamReader(getClass().getResourceAsStream("gcmtestvectors/gcmEncryptExtIV128.rsp"))
        );
        String str;
        do {
            str = in.readLine();
        } while (!str.contains("="));
        
        for ( int i = 0; i < 5; i++ ) {
            
        }
        
        
        in.close();
    }
*/
/*
    @Test
    public void testNISTEx() {
        System.out.println("NIST SP 800-38D Ex");
        byte[] Key = Bin.toByteArray("5fb4b9ff34fb48c4bc93f3531971aaf7");
        byte[] IV = Bin.toByteArray("31e5b67e9a1935e69b0245c0699c0e030da0236f381c9c5bb72247f113e761ce10df91d1296e6d1b65a8e08f1abfa216f43722c24fe63934d3a6bba2861c89073d9f131e7a322b47bc2026b20dbcc7fc6dab8235197d427033bb74d0c2cf0ae400609bf5672632f2567e13a86f9f2d80d2284a6a5d04032c9558c0262a278c1c");
        byte[] CT = new byte[0];
        byte[] AAD = Bin.toByteArray("a31727c34a18be2e7d62d43c59929720d005ac320361b2304e49f5c46f689b9510b491d686e3c7b59badd207179d852a");
        byte[] Tag = Bin.toByteArray("1f04c7a52e5367de8f811125");
        
        GCM gcm = new GCM(new AES());
        gcm.init(Key,IV,AAD);
        gcm.decrypt(CT);
        assertArrayEquals(Tag, gcm.tag());
    }
*/
}
