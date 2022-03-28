package net.siisise.security.digest;

import java.io.UnsupportedEncodingException;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class MD5Test {

    public MD5Test() {
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
        MD5 md = new MD5();
        //SiisiseJCA jca = new SiisiseJCA();
        byte[] d;

        d = md.digest("".getBytes("utf-8"));
        assertArrayEquals(toHex("d41d8cd98f00b204e9800998ecf8427e"), d);
        d = md.digest("a".getBytes("utf-8"));
        assertArrayEquals(toHex("0cc175b9c0f1b6a831c399e269772661"), d);
        d = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(toHex("900150983cd24fb0d6963f7d28e17f72"), d);
        d = md.digest("message digest".getBytes("utf-8"));
        assertArrayEquals(toHex("f96b697d7cb7938d525a2f31aaf161d0"), d);
        d = md.digest("abcdefghijklmnopqrstuvwxyz".getBytes("utf-8"));
        assertArrayEquals(toHex("c3fcd3d76192e4007dfb496cca67e13b"), d);
        d = md.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes("utf-8"));
        assertArrayEquals(toHex("d174ab98d277d9f5a5611c2c9f419d9f"), d);
        d = md.digest("12345678901234567890123456789012345678901234567890123456789012345678901234567890".getBytes("utf-8"));
        assertArrayEquals(toHex("57edf4a22be3c955ac49da2e2107b67a"), d);
    }

}
