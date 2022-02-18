package net.siisise.security;

import java.security.MessageDigest;
import net.siisise.security.digest.SHA256;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class HKDFTest {
    
    public HKDFTest() {
    }

    private byte[] toHex(String src) {
        String b;
        byte[] data = new byte[src.length() / 2];
        for ( int i = 0; i < src.length(); i+= 2) {
            b = src.substring(i,i+2);
            data[i/2] = (byte) Integer.parseInt(b, 16);
        }
        return data;
    }
    
    @Test
    public void testSomeMethod() {
        byte[] s = new byte[1];
        MessageDigest md = new SHA256();
        HKDF hk = new HKDF(md);
        byte[] ikm = toHex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        byte[] salt = toHex("000102030405060708090a0b0c");
        byte[] info = toHex("f0f1f2f3f4f5f6f7f8f9");
        byte[] ep = toHex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        byte[] er = toHex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
        byte[] prk = hk.extract(salt, ikm);
        assertArrayEquals(ep,prk);

        byte[] r = hk.hkdf(salt, ikm, info, 42);
        assertArrayEquals(er,r);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }
    
}
