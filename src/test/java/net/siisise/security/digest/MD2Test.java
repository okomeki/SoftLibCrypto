package net.siisise.security.digest;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class MD2Test {
    
    public MD2Test() {
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
        MessageDigest md = new MD2();
        byte[] d;
        
        d = md.digest("".getBytes("utf-8"));
        assertArrayEquals(toHex("8350e5a3e24c153df2275c9f80692773"), d);
        d = md.digest("a".getBytes("utf-8"));
        assertArrayEquals(toHex("32ec01ec4a6dac72c0ab96fb34c0b5d1"), d);
        d = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(toHex("da853b0d3f88d99b30283a69e6ded6bb"), d);
        d = md.digest("message digest".getBytes("utf-8"));
        assertArrayEquals(toHex("ab4f496bfb2a530b219ff33031fe06b0"), d);
        d = md.digest("abcdefghijklmnopqrstuvwxyz".getBytes("utf-8"));
        assertArrayEquals(toHex("4e8ddff3650292ab5a4108c3aa47940b"), d);
        d = md.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes("utf-8"));
        assertArrayEquals(toHex("da33def2a42df13975352846c30338cd"), d);
        d = md.digest("12345678901234567890123456789012345678901234567890123456789012345678901234567890".getBytes("utf-8"));
        assertArrayEquals(toHex("d5976f79d83d3a0dc9806c3c66f3efd8"), d);
        
        md = new CRC();
        d = md.digest("abcd".getBytes());
        assertArrayEquals(toHex("ed82cd11"), d);
        
    }

    
}
