/*
 * Copyright 2026 okome.
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
package net.siisise.security.sign;

import java.math.BigInteger;
import net.siisise.ietf.pkcs1.PKCS1;

/**
 * RFC 6979
 * 決定的
 * ToDo: 仮
 */
public class Deterministic {

    int qlen;
    
    Deterministic(int qlen) {
        this.qlen = qlen;
    }
    
    /**
     * RFC 6979 2.3.2.
     * @param seq ビットシーケンス (左詰め)
     * @param qlen 出力可能ビットサイズ
     * @return 非負整数
     */
    public static BigInteger bits2int(byte[] seq, int qlen) {
        BigInteger n = PKCS1.OS2IP(seq);
        int blen = n.bitLength();
        if (blen > qlen) {
            n = n.shiftRight(blen - qlen);
        }
        return n;
    }

    public BigInteger bits2int(byte[] seq) {
        return bits2int(seq, qlen);
    }

    /**
     * RFC 6979 2.3.3. Integer to Octet String
     * int2octets(x)
     * SEC 1 Section 2.3.7 Integer-to-OctetString
     * PKCS1 I2OSP と同じ
     * ECDSA ではバイトで指定?
     * 
     * rlen = (qlen + 7) / 8
     * @param x 正の整数
     * @param qlen 出力ビットサイズ rlenの元
     * @return オクテット列 Octet String
     */
    public static byte[] int2octets(BigInteger x, int qlen) {
        return PKCS1.I2OSP(x, (qlen + 7)/8);
    }

    /**
     * 2.3.3. Integer to Octet String
     * int2octets(x)
     * @param x 正の整数
     * @return オクテット列
     */
    public byte[] int2octets(BigInteger x) {
        return int2octets(x, qlen);
    }

    /**
     * RFC 6979 2.3.4. Bit String to Octet String
     * 
     * @param b blenビットのビット列
     * @param rlen 出力ビット長 8の倍数ビット
     * @param q
     * @return オクテット列
     */
    public static byte[] bits2octets(byte[] b, int rlen, BigInteger q) {
        BigInteger z1 = bits2int(b, q.bitLength());
        BigInteger z2 = z1.mod(q);
        return int2octets(z2,rlen);
    }
    
    public byte[] bits2octets(byte[] b, BigInteger q) {
        BigInteger z1 = bits2int(b);
        BigInteger z2 = z1.mod(q);
        return int2octets(z2);
    }

    static int rlen(int qlen) {
        return (qlen + 7) / 8 * 8;
    }

}
