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

import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.lang.Bin;
import net.siisise.security.io.BlockOutput;

/**
 * SHA-2.
 * FIPS PUB 180-2
 * FIPS PUB 180-3
 * RFC 6234
 */
public class SHA256 extends BlockMessageDigest {

    public static final OBJECTIDENTIFIER nistAlgorithm = new OBJECTIDENTIFIER("2.16.840.1.101.3.4");
    /**
     * hashAlgs :== nistAlgorithm 2
     * 
     * 1 sha-256
     * 2 sha-384
     * 3 sha-512
     * 4 sha-224
     * 5 sha-512/224
     * 6 sha-512/256
     * 7 sha3-224
     * 8 sha3-256
     * 9 sha3-384
     * 10 sha3-512
     * 11 shake128
     * 12 shake256
     * 13 hmacWithSHA3-224
     * 14 hmacWithSHA3-256
     * 15 hmacWithSHA3-384
     * 16 hmacWithSHA3-512
     * 17 shake128-len length INTEGER
     * 18 shake256-len length INTEGER
     * 19 KMACWithSHAKE128 length INTEGER default 256, customizationString OCTETSTRING
     * 20 KMACWithSHAKE256 length INTEGER default 512, customizationString OCTETSTRING
     * 21 KMAC128
     * 22 KMAC256
     * 
     */
    public static final OBJECTIDENTIFIER hashAlgs = nistAlgorithm.sub(2);
    public static final OBJECTIDENTIFIER OID = hashAlgs.sub(1 );

    static final int[] IV256 = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };

    static final int[] K = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    final int[] H = new int[8];
    private final int[] IV;

    public SHA256() {
        this("SHA-256",IV256);
    }

    protected SHA256(String n, int[] iv) {
        super(n);
        IV = iv;
        engineReset();
    }

    @Override
    protected int engineGetDigestLength() {
        return 32;
    }

    @Override
    public int getBitBlockLength() {
        return 512;
    }

    @Override
    protected void engineReset() {
        System.arraycopy(IV, 0, H, 0, IV.length);
        pac = new BlockOutput(this);
        length = 0;
    }

    private static int Ch(final int x, final int y, final int z) {
        return (x & y) ^ ((~x) & z);
    }

    private static int Maj(final int x, final int y, final int z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    private static int ROTR(final int x, final int n) {
        return (x >>> n) | (x << (32 - n));
    }

    private static int Σ0(final int x) {
        return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
    }

    private static int Σ1(final int x) {
        return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
    }

    private static int σ0(final int x) {
        return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >>> 3);
    }

    private static int σ1(final int x) {
        return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >>> 10);
    }

    int w[] = new int[64];

    @Override
    public void blockWrite(byte[] in, int offset, int length) {

        int a, b, c, d, e, f, g, h;
        a = H[0];
        b = H[1];
        c = H[2];
        d = H[3];
        e = H[4];
        f = H[5];
        g = H[6];
        h = H[7];

        Bin.btoi(in, offset, w, 16);
        for (int t = 16; t < 64; t++) {
            w[t] = σ1(w[t - 2]) + w[t - 7] + σ0(w[t - 15]) + w[t - 16];
        }

        for (int t = 0; t < 64; t++) {
            int temp1 = h + Σ1(e) + Ch(e, f, g) + K[t] + w[t];
            int temp2 = Σ0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
/*
        // シフトしているのは元に戻る
        for (int t = 63; t >=0; t--) {
            int temp1 = a;
            a = b;
            b = c;
            c = d;
            int temp2 = Σ0(a) + Maj(a, b, c);
            temp1 -= temp2;
            d = e - temp1;
            e = f;
            f = g;
            g = h;
            h = temp1 - (Σ1(e) + Ch(e, f, g) + K[t] + w[t]); // h か wが定まらないと不確定
        }
        for (int t = 0; t < 64; t++) {
            int temp1 = h + Σ1(e) + Ch(e, f, g) + K[t] + w[t];
            int temp2 = Σ0(a) + Maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }
*/
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    /**
     * int列をbyte列に変換するだけ。 big endianかな
     * @param src データint列
     * @param len 出力バイト長
     * @return 
     */
    public static byte[] toB(int[] src, int len) {
        byte[] ret = new byte[len];
        for (int i = 0; i < len; i++) {
            ret[i] = (byte) (src[i / 4] >>> (((3 - i) % 4) * 8));
        }
        return ret;
    }

    @Override
    protected byte[] engineDigest() {

        long len = length;

        // ラスト周
        // padding
        pac.write(new byte[]{(byte) 0x80});
        int padlen = 512 - (int) ((len + 64 + 8) % 512);
        pac.write(new byte[padlen / 8]);
        byte[] lena = new byte[8];
        for (int i = 0; i < 8; i++) {
            lena[7 - i] = (byte) len;
            len >>>= 8;
        }

        pac.write(lena, 0, lena.length);

        byte[] ret = toB(H, engineGetDigestLength());
        engineReset();
        return ret;
    }

}
