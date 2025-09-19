/*
 * Copyright 2023 Siisise Net.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.siisise.security.digest;

import java.io.UnsupportedEncodingException;
import net.siisise.lang.Bin;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class MD5Test {

    public MD5Test() {
    }

    @Test
    public void testSomeMethod() throws UnsupportedEncodingException {
        System.out.println("MD5:");
        MD5 md = new MD5();
        //SiisiseJCA jca = new SiisiseJCA();
        byte[] d;

        d = md.digest("".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("d41d8cd98f00b204e9800998ecf8427e"), d);
        d = md.digest("a".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("0cc175b9c0f1b6a831c399e269772661"), d);
        d = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("900150983cd24fb0d6963f7d28e17f72"), d);
        d = md.digest("message digest".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("f96b697d7cb7938d525a2f31aaf161d0"), d);
        d = md.digest("abcdefghijklmnopqrstuvwxyz".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("c3fcd3d76192e4007dfb496cca67e13b"), d);
        d = md.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("d174ab98d277d9f5a5611c2c9f419d9f"), d);
        d = md.digest("12345678901234567890123456789012345678901234567890123456789012345678901234567890".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("57edf4a22be3c955ac49da2e2107b67a"), d);
    }

}
