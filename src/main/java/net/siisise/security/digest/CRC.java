/*
 * Copyright 2021 Siisise Net.
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

import java.security.MessageDigest;

/**
 * 巡回冗長検査.
 * IEEE 802.3. CRC-32 GF(2)
 *
 * ZIPやPNGなどて使われたり.
 * CRC8,16,32と64があるかもしれない.
 * CRC8
 * CRC8-CCITT CRC8-SAE CRC8-ATM CRC8-Dallas/Maxum
 * RFC 1952 gzip RFC 2083 PNG
 * CRC-32 Wikipedia のものを実装
 */
public class CRC extends MessageDigest {

    static final int[] crc = new int[256];

    static {
        // ビット反転版GF 32bit の8ビットくり抜き?
        for (int i = 0; i < 256; i++) {
            int c = i;
            for (int j = 0; j < 8; j++) { // iが8bitしかないので8回?
                c = (c >>> 1) ^ ((c & 1) * 0xedb88320);
            }
            crc[i] = c;
        }
    }

    int c;

    public CRC() {
        super("CRC-32");
        engineReset();
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        for (int i = offset; i < offset + len; i++) {
            c = crc[(c ^ input[i]) & 0xff] ^ (c >>> 8);
//            c = (c << 8) ^ crc[((c >>> 24) ^ input[i]) & 0xff];
        }
    }

    @Override
    protected byte[] engineDigest() {
        c ^= 0xffffffff;
        //engineUpdate(new byte[4], 0, 4);
        byte[] cr = new byte[4];
        cr[0] = (byte) ((c >>> 24) & 0xff);
        cr[1] = (byte) ((c >>> 16) & 0xff);
        cr[2] = (byte) ((c >>> 8) & 0xff);
        cr[3] = (byte) (c & 0xff);
//        System.out.println(Integer.toHexString(c));
        engineReset();
        return cr;
    }

    @Override
    protected void engineReset() {
        c = 0xffffffff;
    }

}
