/*
 * Copyright 2022-2023 okome.
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
package net.siisise.security.key;

import java.math.BigInteger;
import net.siisise.security.block.RSA;

/**
 * RFC 8017 PKCS #1 3.2.
 * RSA Private Key (RSA秘密鍵)
 * X.509 系Encode出力には未対応.
 */
public class RSAMiniPrivateKey implements java.security.interfaces.RSAPrivateKey {

    private static final long serialVersionUID = 1L;

    /**
     * n : thr RSA modulus, a positive integer n = pq
     */
    BigInteger modulus;          // n = pq 公開

    /**
     * d : the RSA private exponent, a positive integer
     */
    BigInteger privateExponent;  // d = e^(-1) mod (p-1)(q-1) 秘密

    /**
     * 継承用など
     */
    protected RSAMiniPrivateKey() {
    }

    public RSAMiniPrivateKey(BigInteger n, BigInteger d) {
        modulus = n;
        privateExponent = d;
    }

    /**
     * RSA Decryption Primitive
     * 5.1.2. RSADP
     * m = c ^ d ( mod n ) オプションは省略する.
     *
     * @param c ciphertext 暗号文 0 ～ n - 1 の整数
     * @return m プレーンテキスト 0 ～ n - 1 の範囲
     * @see RSAPublicKey#rsaep(java.math.BigInteger) 
     */
    public BigInteger rsadp(BigInteger c) {
        if (c.compareTo(BigInteger.ZERO) < 0 || c.compareTo(modulus) >= 0) {
            throw new SecurityException("ciphertext representative out of range");
        }
        return c.modPow(privateExponent, modulus);
    }

    /**
     * RSA Decryption Primitive
     * @param v
     * @return 
     */
    public BigInteger rsadp(byte[] v) {
        return rsadp(RSA.os2ip(v));
    }

    /**
     * 5.2.1. RSASP1
     *
     * @param m
     * @return
     */
    public BigInteger rsasp1(BigInteger m) {
        if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(modulus) >= 0) {
            throw new SecurityException("message representative out of range");
        }
        return m.modPow(privateExponent, modulus);
    }

    public BigInteger modPow(BigInteger s) {
        return s.modPow(privateExponent, modulus);
    }

    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    /**
     * PKCS#8 ぐらい
     *
     * @return
     */
    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * PKCS #1 A.1.2. RSA Private Key Syntax の出力はできない.
     * @return 
     */
    @Override
    public byte[] getEncoded() {

        throw new UnsupportedOperationException("Not supported yet.");
    }
}
