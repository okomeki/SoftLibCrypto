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
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class MD4Test {
    
    public MD4Test() {
    }

    @Test
    public void testSomeMethod() throws UnsupportedEncodingException {
        MD4 md = new MD4();
        byte[] d;
        
        d = md.digest("".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("31d6cfe0d16ae931b73c59d7e0c089c0"), d);
        d = md.digest("a".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("bde52cb31de33e46245e05fbdbd6fb24"), d);
        d = md.digest("abc".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("a448017aaf21d8525fc10ae87aa6729d"), d);
        d = md.digest("message digest".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("d9130a8164549fe818874806e1c7014b"), d);
        d = md.digest("abcdefghijklmnopqrstuvwxyz".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("d79e1c308aa5bbcdeea8ed63df412da9"), d);
        d = md.digest("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("043f8582f241db351ce627e153e7f0e4"), d);
        d = md.digest("12345678901234567890123456789012345678901234567890123456789012345678901234567890".getBytes("utf-8"));
        assertArrayEquals(Bin.toByteArray("e33b4ddc9c38f2199c3e7b164fcc0536"), d);
    }
    
}
