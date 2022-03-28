package net.siisise.security.digest;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.siisise.security.SiisiseJCA;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class SHA256Test {

    public SHA256Test() {
    }

    static String SHA224abc = "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7";
    static String SHA256abc = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    static String SHA384abc = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7";
    static String SHA512abc = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";

    static String SHA224e = "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f";
    static String SHA224m = "730e109bd7a8a32b1cb9d9a09aa2325d2430587ddbc0c38bad911525";
    static String SHA256e = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    static String SHA384e = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b";
    static String SHA512e = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e";
    static String SHA512224e = "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4";
    static String SHA512256e = "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a";

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
    public void testSomeMethod() throws UnsupportedEncodingException {
        MessageDigest md;
        byte[] r;

        md = new SHA224();
        r = md.digest("".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA224e));

        r = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA224abc));

        r = md.digest("The quick brown fox jumps over the lazy dog".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA224m),"SHA-224");

        md.update("The quick brown fox ".getBytes());
        r = md.digest("jumps over the lazy dog".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA224m),"SHA-224");
//        r = md.digest("abc".getBytes("utf-8"));
//        assertArrayEquals(r,toHex(SHA224e));
        
        md = new SHA256();
        r = md.digest("".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA256e),"SHA-256");

        r = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA256abc),"SHA-256");
        
        md = new SHA384();
        r = md.digest("".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA384e),"SHA-384");

        r = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA384abc),"SHA-384");
        
        md = new SHA512();
        r = md.digest("".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA512e),"SHA-512");

        r = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA512abc),"SHA-512");

        md = new SHA512(224);
        r = md.digest("".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA512224e),"SHA-512/224");

        md = new SHA512256();
        r = md.digest("".getBytes("utf-8"));
        assertArrayEquals(r,toHex(SHA512256e),"SHA-512/256");
        
        SiisiseJCA jca = new SiisiseJCA();
        Security.addProvider(jca);
        
        try {
            md = MessageDigest.getInstance("SHA-512/224",jca);
            r = md.digest("".getBytes("utf-8"));
            assertArrayEquals(r,toHex(SHA512224e),"SHA-512/224");

            md = MessageDigest.getInstance("SHA-512/256",jca);
            r = md.digest("".getBytes("utf-8"));
            assertArrayEquals(r,toHex(SHA512256e),"SHA-512/256");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SHA256Test.class.getName()).log(Level.SEVERE, null, ex);
        }

        
    }
    
}
