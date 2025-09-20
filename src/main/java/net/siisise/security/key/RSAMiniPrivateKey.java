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
import java.security.PrivateKey;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 8017 PKCS #1 3.2.
 * RSA Private Key (RSA秘密鍵)
 * n と d だけ持っている最小版.
 * X.509 系Encode出力には未対応.
 */
public class RSAMiniPrivateKey implements PrivateKey, java.security.interfaces.RSAPrivateKey {

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

    /**
     * 秘密鍵要素のみ
     * @param n modulus
     * @param d privateExponent
     */
    public RSAMiniPrivateKey(BigInteger n, BigInteger d) {
        modulus = n;
        privateExponent = d;
    }

    /**
     * RSA Decryption Primitive
     * RFC 8017 5.1.2. RSADP
     * m = c ^ d ( mod n ) オプションは省略する.
     *
     * @param c ciphertext 暗号文 0 ～ n - 1 の整数
     * @return m message メッセージ 0 - n-1 の整数
     * @see RSAPublicKey#rsaep(java.math.BigInteger) 
     */
    public BigInteger rsadp(BigInteger c) {
        if (c.compareTo(BigInteger.ZERO) < 0 || c.compareTo(modulus) >= 0) {
            throw new SecurityException("ciphertext representative out of range");
        }
        return modPow(c);
    }

    /**
     * RSA Decryption Primitive
     * RSADP(OS2IP(c))
     * @param c ciphertext 暗号文 0 - n-1 の整数
     * @return m message メッセージ 0 - n-1 の整数
     */
    public BigInteger rsadp(byte[] c) {
        return rsadp(PKCS1.OS2IP(c));
    }

    /**
     * I2OSP(RSADP(OS2IP(c)))
     * @param c ciphertext 暗号文 0 ～ n - 1 の整数
     * @param xLen 戻り長さ
     * @return m message メッセージ 0 - n-1 の整数
     */
    public byte[] rsadp(byte[] c, int xLen) {
        return PKCS1.I2OSP(rsadp(PKCS1.OS2IP(c)), xLen);
    }

    /**
     * 5.2.1. RSASP1
     * RSADP と同じ計算
     *
     * @param m メッセージ
     * @return 署名?
     */
    public BigInteger rsasp1(BigInteger m) {
        if (m.compareTo(BigInteger.ZERO) < 0 || m.compareTo(modulus) >= 0) {
            throw new SecurityException("message representative out of range");
        }
        return modPow(m);
    }

    /**
     * 5.2.1. RSASP1
     * RSASP1 の前後の変換をまとめたもの
     * I2OSP(RSASP1(OS2IP(m)),xLen)
     * @param m データ
     * @param xlen 戻りバイト長
     * @return I2OSP(RSASP1(OS2IP(m)),xLen)
     */
    public byte[] rsasp1(byte[] m, int xlen) {
        return PKCS1.I2OSP(rsasp1(PKCS1.OS2IP(m)), xlen);
    }

    /**
     * @param s
     * @return s.modPow(d, n)
     */
    public BigInteger modPow(BigInteger s) {
        return s.modPow(privateExponent, modulus);
    }

    /**
     * private exponent
     * @return d プライベート指数
     */
    @Override
    public BigInteger getPrivateExponent() {
        return privateExponent;
    }

    /**
     * modulus
     * @return n モジュラス
     */
    @Override
    public BigInteger getModulus() {
        return modulus;
    }

    /**
     * 暗号アルゴリズム
     * @return RSA
     */
    @Override
    public String getAlgorithm() {
        return "RSA";
    }

    /**
     * PKCS#1 ぐらい
     *
     * @return
     */
    @Override
    public String getFormat() {
        return "PKCS#1";
    }

    /**
     * PKCS #1 A.1.2. RSA Private Key Syntax の出力はできない.
     * 公開鍵相当にしておく.
     * @return modulus と privateExponent の ASN.1 DER Format
     */
    @Override
    public byte[] getEncoded() {
        SEQUENCEMap seq = getPrivateASN1();
        return (byte[]) seq.rebind(new ASN1DERFormat());
    }

    /**
     * 公開鍵の形式を借り
     * @return 
     */
    public SEQUENCEMap getPrivateASN1() {
        SEQUENCEMap seq = new SEQUENCEMap();
        seq.put("modulus", new INTEGER(modulus)); // n
        seq.put("privateExponent", new INTEGER(privateExponent)); // e
        return seq;
    }
}
