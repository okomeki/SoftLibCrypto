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
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;

/**
 * 公開鍵っぽいところをのせたかな.
 * 署名
 * m = ハッシュ
 * m^d mod n = 署名
 * 署名^e mod n = m
 * 
 * 公開鍵で実装するもの.
 * 5.1.1. RSAEP 
 * 5.2.2. RSAVP1
 * 秘密鍵で実装するもの.
 * 5.1.2. RSADP
 * 5.2.1. RSASP1
 * 
 * ToDo: Section 7 から
 * 
 * ほか
 * 7.1. RSAES-OAEP
 * 7.2. RSAES-PKCS1-v1_5
 * 8.1. RSASSA-PSS
 * 8.2. RSASSA-PKCS1-v1_5
 * 
 * @deprecated まだ不安定かも
 */
@Deprecated
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
        pub = new RSAPublicKey(PKCS1.OS2IP(keyandparam[1]), PKCS1.OS2IP(keyandparam[0]));
        nlen = pub.getModulus().bitLength() / 8;  // keyandparam[1].length - 1; // ToDo: 仮
        if ( keyandparam[1][0] == 0 ) {
            nlen--; // padding 付きなら1つ下げ?
        }
        if ( keyandparam.length > 2) { // 秘密鍵
            key = new RSAMiniPrivateKey(PKCS1.OS2IP(keyandparam[1]), PKCS1.OS2IP(keyandparam[2]));
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
     * RFC 8017 4.1. I2OSP
     * @deprecated net.siisise.ietf.pkcs1.PKCS1#I2OSP(BigInteger,int)
     * @param x データ
     * @param xLen 長さ
     * @return 長さ
     */
    @Deprecated
    public static byte[] i2osp(BigInteger x, int xLen) {
        return PKCS1.I2OSP(x, xLen);
    }

    /**
     * Octet String to Integer primitive
     * 4. Data Conversion Primitives
     * 4.2. OS2IP
     * signed になりそうなものをunsigned に拡張してからBigIntegerにする.
     * @param em 符号略バイトデータ
     * @return 符号なしBigInteger
     */
    public static BigInteger os2ip(byte[] em) {
        return PKCS1.OS2IP(em);
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
