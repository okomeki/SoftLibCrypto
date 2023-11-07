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
import java.security.MessageDigest;
import net.siisise.lang.Bin;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class MD2Test {
    
    public MD2Test() {
    }

    @Test
    public void testSomeMethod() throws UnsupportedEncodingException {
        MessageDigest md = new MD2();
        byte[] d;
        
        d = md.digest("".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("8350e5a3e24c153df2275c9f80692773"), d);
        d = md.digest("a".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("32ec01ec4a6dac72c0ab96fb34c0b5d1"), d);
        d = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("da853b0d3f88d99b30283a69e6ded6bb"), d);
        d = md.digest("message digest".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("ab4f496bfb2a530b219ff33031fe06b0"), d);
        d = md.digest("abcdefghijklmnopqrstuvwxyz".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("4e8ddff3650292ab5a4108c3aa47940b"), d);
        d = md.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("da33def2a42df13975352846c30338cd"), d);
        d = md.digest("12345678901234567890123456789012345678901234567890123456789012345678901234567890".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("d5976f79d83d3a0dc9806c3c66f3efd8"), d);
        
        md = new CRC();
        d = md.digest("abcd".getBytes());
        assertArrayEquals(Bin.toByteArray("ed82cd11"), d);
        
    }

    
}
