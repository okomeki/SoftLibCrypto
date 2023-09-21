/*
 * Copyright 2023 okome.
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

import java.math.BigInteger;
import net.siisise.io.BigBitPacket;
import net.siisise.io.BitPacket;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;

/**
 * NIST Special Publication 800-185
 */
public class SHA3Derived {
    
    /**
     * 正の整数.
     * 末尾に長さ情報が付く?
     * NIST SP 800-185 2.3.1
     * 255 文字 - 1 bit まで
     * @param x 0 &lt;= x &lt; 2^2040
     * @return 
     */
    public static byte[] right_encode(BigInteger x) {
        byte[] is = x.toByteArray();
        byte[] r = new byte[is.length + 1];
        System.arraycopy(is, 0, r, 0, is.length);
        r[is.length] = (byte)is.length;
        return r;
    }

    public static byte[] right_encode(long x) {
        byte[] is = BigInteger.valueOf(x).toByteArray();
        byte[] r = new byte[is.length + 1];
        System.arraycopy(is, 0, r, 0, is.length);
        r[is.length] = (byte)is.length;
        return r;
    }

    /**
     * 正の整数.
     * 先頭に長さ情報が付く.
     * @param x 0 &lt;= x &lt; 2^2040
     * @return 
     */
    public static byte[] left_encode(BigInteger x) {
        byte[] is = x.toByteArray();
        byte[] r = new byte[is.length + 1];
        System.arraycopy(is, 0, r, 1, is.length);
        r[0] = (byte)is.length;
        return r;
    }

    /**
     * 正の整数.
     * @param x
     * @return 
     */
    public static byte[] left_encode(long x) {
        byte[] is = BigInteger.valueOf(x).toByteArray();
        byte[] r = new byte[is.length + 1];
        System.arraycopy(is, 0, r, 1, is.length);
        r[0] = (byte)is.length;
        return r;
    }
    
    /**
     * NIST SP 800-185 2.3.2. String Encoding
     * @param s bit string
     * @return 
     */
    public static Packet encode_string(byte[] s) {
        Packet p = new PacketA();
        p.write(left_encode(len(s)));
        p.write(s);
        return p;
    }
    
    public static Packet encode_string(byte[] s, int offset, int length) {
        Packet p = new PacketA();
        p.write(left_encode(length * 8l));
        p.write(s, offset, length);
        return p;
    }

    /**
     * 
     * @param s
     * @return 
     */
    public static BitPacket encode_string(BitPacket s) {
        BitPacket p = new BigBitPacket();
        p.write(left_encode(len(s)));
        p.writeBit(s);
        return p;
    }
    
    static long len(byte[] s) {
        return s.length * 8l;
    }
    
    /**
     * ビット長.
     * @param s でーた
     * @return bitlength
     */
    static long len(BitPacket s) {
        return s.bitLength();
    }

    /**
     * ビット列に長さを付加してwバイト単位でパディングする
     * 2.3.3 Padding
     * @param X ビット列
     * @param w &gt; 0
     * @return 
     */
    static byte[] bytepad(BitPacket X, int w) {
        BitPacket z = new BigBitPacket();
        z.write(left_encode(w));
        z.writeBit(X);
        long zl = z.bitLength() % 8;
        if ( zl != 0) {
            z.writeBit(0, (int)(8- zl));
        }
        zl = z.length() % w;
        if ( zl != 0) {
            z.write(new byte[(int)(w - zl)]);
        }
        return z.toByteArray();
    }

    public static byte[] bytepad(Packet X, int w) {
        Packet z = new PacketA();
        z.write(left_encode(w));
        z.write(X);
        long zl = z.length() % w;
        if ( zl != 0) {
            z.write(new byte[(int)(w - zl)]);
        }
        return z.toByteArray();
    }

    public static byte[] bytepad(byte[] X, int w) {
        Packet z = new PacketA();
        z.write(left_encode(w));
        z.write(X);
        long zl = z.length() % w;
        if ( zl != 0) {
            z.write(new byte[(int)(w - zl)]);
        }
        return z.toByteArray();
    }
    
    /**
     * 2.3.4 Substrings
     * @param X
     * @param a
     * @param b
     * @return 
     */
    static BitPacket substring(BitPacket X, long a, long b) {
        if ( a >= b || a >= len(X)) {
            return new BigBitPacket();
        } else if ( b > len(X)) {
            b = len(X);
        } else {
        }
        byte[] tmp = new byte[(int)((b - a + 7) / 8)];
        BitPacket f = X.readPac((int)a);
        X.readBit(tmp, 0, b - a);
        X.backWriteBit(tmp, 0, b - a);
        X.backWriteBit(f);
        BitPacket n = new BigBitPacket();
        n.writeBit(tmp, 0, b - a);
        return n;
    }

}
