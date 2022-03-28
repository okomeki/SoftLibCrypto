package net.siisise.security.digest;

import java.io.UnsupportedEncodingException;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class MD4Test {
    
    public MD4Test() {
    }

    private byte[] toHex(String src) {
        String b;
        byte[] data = new byte[src.length() / 2];
        for (int i = 0; i < src.length(); i += 2) {
            b = src.substring(i, i + 2);
            data[i / 2] = (byte) Integer.parseInt(b, 16);
        }
        return data;
    }

    @Test
    public void testSomeMethod() throws UnsupportedEncodingException {
        MD4 md = new MD4();
        byte[] d;
        
        d = md.digest("".getBytes("utf-8"));
        assertArrayEquals(toHex("31d6cfe0d16ae931b73c59d7e0c089c0"), d);
        d = md.digest("a".getBytes("utf-8"));
        assertArrayEquals(toHex("bde52cb31de33e46245e05fbdbd6fb24"), d);
        d = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(toHex("a448017aaf21d8525fc10ae87aa6729d"), d);
        d = md.digest("message digest".getBytes("utf-8"));
        assertArrayEquals(toHex("d9130a8164549fe818874806e1c7014b"), d);
        d = md.digest("abcdefghijklmnopqrstuvwxyz".getBytes("utf-8"));
        assertArrayEquals(toHex("d79e1c308aa5bbcdeea8ed63df412da9"), d);
        d = md.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes("utf-8"));
        assertArrayEquals(toHex("043f8582f241db351ce627e153e7f0e4"), d);
        d = md.digest("12345678901234567890123456789012345678901234567890123456789012345678901234567890".getBytes("utf-8"));
        assertArrayEquals(toHex("e33b4ddc9c38f2199c3e7b164fcc0536"), d);
    }
    
}
