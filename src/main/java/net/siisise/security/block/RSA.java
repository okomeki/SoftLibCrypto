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
package net.siisise.security.block;

import java.math.BigInteger;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;

/**
 * 公開鍵っぽいところをのせたかな.
 * 署名
 * m = ハッシュ
 * m^d mod n = 署名
 * 署名^e mod n = m
 * @deprecated まだ不安定かも
 */
public class RSA extends OneBlock {

    RSAMiniPrivateKey key;
    RSAPublicKey pub;

    int nlen;

    /**
     * (nの)ビット長 - 24(padding) ぐらい.
     * init後に.
     */
    @Override
    public int getBlockLength() {
        return nlen * 8;
    }

    /**
     * 秘密鍵/公開鍵 初期化.
     * @param keyandparam e, n, d の順 (d省略可)
     */
    @Override
    public void init(byte[]... keyandparam) {
        pub = new RSAPublicKey(os2ip(keyandparam[1]), os2ip(keyandparam[0]));
        nlen = pub.getModulus().bitLength() / 8;  // keyandparam[1].length - 1; // ToDo: 仮
        if ( keyandparam[1][0] == 0 ) {
            nlen--; // padding 付きなら1つ下げ?
        }
        if ( keyandparam.length > 2) { // 秘密鍵
            key = new RSAMiniPrivateKey(os2ip(keyandparam[1]), os2ip(keyandparam[2]));
        }
    }

    public void init(RSAMiniPrivateKey prv) {
        key = prv;
    }

    public void init(RSAPublicKey pb) {
        pub = pb;
    }

    /**
     * Integer to Octet String primitive
     * @param x
     * @param xLen
     * @return 長さ
     */
    public static byte[] i2osp(BigInteger x, int xLen) {
        byte[] xnum = x.toByteArray();
        if ( xnum.length != xLen ) {
            if ( xnum.length < xLen ) {
                byte[] t = new byte[xLen];
                System.arraycopy(xnum, 0, t, xLen - xnum.length, xnum.length);
                xnum = t;
            } else if (xnum.length == xLen + 1 && xnum[0] == 0) { // delete flag
                byte[] t = new byte[xLen];
                System.arraycopy(xnum, 1, t, 0, xnum.length);
                xnum = t;
            } else if ( xnum.length > xLen ) {
                throw new SecurityException("integer too large");
            }
        }
        return xnum;
    }

    /**
     * Octet String to Integer primitive
     * 4. Data Conversion Primitives
     * signed になりそうなものをunsigned に拡張してからBigIntegerにする.
     * @param em 符号略バイトデータ
     * @return 符号なしBigInteger
     */
    public static BigInteger os2ip(byte[] em) {
        if ( em[0] < 0) {
            byte[] unum = new byte[em.length + 1];
            System.arraycopy(em, 0, unum, 1, em.length);
            return new BigInteger(unum);
        }
        return new BigInteger(em);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        byte[] s = new byte[nlen - 3];
        int len = Integer.min(src.length - offset, nlen - 3);
        System.arraycopy(src, offset, s, s.length - len, len);
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * 秘密鍵で
     * @param src 暗号文
     * @param offset 見ない?
     * @return 
     */
    @Override
    public byte[] decrypt(byte[] src, int offset) {
        BigInteger r = key.rsadp(src);
        byte[] dec = r.toByteArray();
        if ( dec[0] != 1) {
            throw new SecurityException();
        }
        int i = 1;
        while ((dec[i] & 0xff) == 0xff) {
            i++;
        }
        if (dec[i++] != 0) {
            throw new SecurityException();
        }
        byte[] dd = new byte[dec.length - i];
        System.arraycopy(dec,i,dd,0,dec.length - i);
        return dd;
    }
}
