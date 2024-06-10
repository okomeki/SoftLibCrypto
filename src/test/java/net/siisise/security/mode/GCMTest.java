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
     * NIST 
     * https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf
     */
    @Test
    public void testAES_GCM() {
        System.out.println("GCM-AES128 Example #1");
        byte[] K = Bin.toByteArray("FEFFE9928665731C6D6A8F9467308308");
        byte[] IV = Bin.toByteArray("CAFEBABEFACEDBADDECAF888");
        byte[] exTag = Bin.toByteArray("3247184B3C4F69A44DBCD22887BBB418");
        GCM gcm = new GCM(new AES());
        gcm.init(K, IV);
        byte[] C = gcm.encrypt(new byte[0]);
        assertEquals(0, C.length);
        byte[] t = gcm.tag();
        System.out.println("Cipher(K, J0) = " + Bin.toUpperHex(t));
        assertArrayEquals(exTag, t);
        gcm = new GCM(new AES());
        gcm.init(K, IV);
        byte[] E = gcm.decrypt(new byte[0]);
        t = gcm.tag();
        assertArrayEquals(exTag, t);
    }

    /**
     * Example #2
     * Taglen = 128
     * ADDlen = 0
     * PTlen = 512
     */
    @Test
    public void testAES_GCM_ex2() {
        System.out.println("GCM-AES128 Example #2");
        byte[] K = Bin.toByteArray("FEFFE9928665731C6D6A8F9467308308");
        byte[] IV = Bin.toByteArray("CAFEBABEFACEDBADDECAF888");
        byte[] P = Bin.toByteArray("D9313225F88406E5A55909C5AFF5269A"
                                 + "86A7A9531534F7DA2E4C303D8A318A72"
                                 + "1C3C0C95956809532FCF0E2449A6B525"
                                 + "B16AEDF5AA0DE657BA637B391AAFD255");
        byte[] exC = Bin.toByteArray("42831EC2217774244B7221B784D0D49C"
                                   + "E3AA212F2C02A4E035C17E2329ACA12E"
                                   + "21D514B25466931C7D8F6A5AAC84AA05"
                                   + "1BA30B396A0AAC973D58E091473F5985");
        byte[] exTag = Bin.toByteArray("4D5C2AF327CD64A62CF35ABD2BA6FAB4");
        GCM gcm = new GCM();
        gcm.init(K, IV);
        byte[] C = gcm.encrypt(P);
        byte[] t = gcm.tag();
        
        System.out.println("C = CT is " + Bin.toUpperHex(C));

        System.out.println("Tag = " + Bin.toUpperHex(t));
        assertArrayEquals(exC, C);
        assertArrayEquals(exTag, t);
        
        gcm = new GCM();
        gcm.init(K, IV);
        byte[] deP = gcm.decrypt(exC);
        assertArrayEquals(P, deP);
        t = gcm.tag();
        assertArrayEquals(exTag, t);
    }

    /**
     * Example #2
     * Taglen = 128
     * ADDlen = 512
     * PTlen = 0
     */
    @Test
    public void testAES_GCM_ex3() {
        System.out.println("GCM-AES128 Example #3");
        byte[] K = Bin.toByteArray("FEFFE9928665731C6D6A8F9467308308");
        byte[] IV = Bin.toByteArray("CAFEBABEFACEDBADDECAF888");
        byte[] A = Bin.toByteArray("3AD77BB40D7A3660A89ECAF32466EF97"
                + "F5D3D58503B9699DE785895A96FDBAAF"
                + "43B1CD7F598ECE23881B00E3ED030688"
                + "7B0C785E27E8AD3F8223207104725DD4");
        byte[] P = new byte[0];
        byte[] exTag = Bin.toByteArray("5F91D77123EF5EB9997913849B8DC1E9");
        GCM gcm = new GCM();
        gcm.init(K, IV, A);
        byte[] C = gcm.encrypt(P);
        byte[] t = gcm.tag();
        
//        System.out.println("C = CT is " + Bin.toUpperHex(C));

        System.out.println("Tag = " + Bin.toUpperHex(t));
//        assertArrayEquals(exC, C);
        assertArrayEquals(exTag, t);
        
        gcm = new GCM();
        gcm.init(K, IV, A);
        byte[] deP = gcm.decrypt(C);
        assertArrayEquals(P, deP);
        t = gcm.tag();
        assertArrayEquals(exTag, t);
    }

    /**
     * Example #4
     * Taglen = 128
     * ADDlen = 512
     * PTlen = 512
     */
    @Test
    public void testAES_GCM_ex4() {
        System.out.println("GCM-AES128 Example #4");
        byte[] K = Bin.toByteArray("FEFFE9928665731C6D6A8F9467308308");
        byte[] IV = Bin.toByteArray("CAFEBABEFACEDBADDECAF888");
        byte[] A = Bin.toByteArray("3AD77BB40D7A3660A89ECAF32466EF97"
                                 + "F5D3D58503B9699DE785895A96FDBAAF"
                                 + "43B1CD7F598ECE23881B00E3ED030688"
                                 + "7B0C785E27E8AD3F8223207104725DD4");
        byte[] P = Bin.toByteArray("D9313225F88406E5A55909C5AFF5269A"
                                 + "86A7A9531534F7DA2E4C303D8A318A72"
                                 + "1C3C0C95956809532FCF0E2449A6B525"
                                 + "B16AEDF5AA0DE657BA637B391AAFD255");
        byte[] exC = Bin.toByteArray("42831EC2217774244B7221B784D0D49C"
                                   + "E3AA212F2C02A4E035C17E2329ACA12E"
                                   + "21D514B25466931C7D8F6A5AAC84AA05"
                                   + "1BA30B396A0AAC973D58E091473F5985");
        byte[] exTag = Bin.toByteArray("64C0232904AF398A5B67C10B53A5024D");
        GCM gcm = new GCM();
        gcm.init(K, IV, A);
        byte[] C = gcm.encrypt(P);
        byte[] t = gcm.tag();
        
        System.out.println("C = CT is " + Bin.toUpperHex(C));

        System.out.println("Tag = " + Bin.toUpperHex(t));
        assertArrayEquals(exC, C);
        assertArrayEquals(exTag, t);
        
        gcm = new GCM();
        gcm.init(K, IV, A);
        byte[] deP = gcm.decrypt(exC);
        assertArrayEquals(P, deP);
        t = gcm.tag();
        assertArrayEquals(exTag, t);
    }

    /**
     * Example #4
     * Taglen = 128
     * ADDlen = 160
     * PTlen = 480
     */
    @Test
    public void testAES_GCM_ex5() {
        System.out.println("GCM-AES128 Example #5");
        byte[] K = Bin.toByteArray("FEFFE9928665731C6D6A8F9467308308");
        byte[] IV = Bin.toByteArray("CAFEBABEFACEDBADDECAF888");
        byte[] A = Bin.toByteArray("3AD77BB40D7A3660A89ECAF32466EF97"
                                 + "F5D3D585");
        byte[] P = Bin.toByteArray("D9313225F88406E5A55909C5AFF5269A"
                                 + "86A7A9531534F7DA2E4C303D8A318A72"
                                 + "1C3C0C95956809532FCF0E2449A6B525"
                                 + "B16AEDF5AA0DE657BA637B39");
        byte[] exC = Bin.toByteArray("42831EC2217774244B7221B784D0D49C"
                                   + "E3AA212F2C02A4E035C17E2329ACA12E"
                                   + "21D514B25466931C7D8F6A5AAC84AA05"
                                   + "1BA30B396A0AAC973D58E091");
        byte[] exTag = Bin.toByteArray("F07C2528EEA2FCA1211F905E1B6A881B");
        GCM gcm = new GCM();
        gcm.init(K, IV, A);
        byte[] C = gcm.encrypt(P);
        byte[] t = gcm.tag();
        
        System.out.println("C = CT is " + Bin.toUpperHex(C));

        System.out.println("Tag = " + Bin.toUpperHex(t));
        assertArrayEquals(exC, C);
        assertArrayEquals(exTag, t);
        
        gcm = new GCM();
        gcm.init(K, IV, A);
        byte[] deP = gcm.decrypt(exC);
        assertArrayEquals(P, deP);
        t = gcm.tag();
        assertArrayEquals(exTag, t);
    }

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
