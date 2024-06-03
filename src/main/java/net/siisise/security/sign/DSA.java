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
package net.siisise.security.sign;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;

/**
 * FIPS PUB 186-4
 * DOI https://doi.org/10.6028/NIST.FIPS.186-4
 * Section 4. DSA
 * DSA, ECDSA
 * RFC 6979
 * 
 * 入力
 *  k 乱数値 毎回必要
 * 
 */
public class DSA implements SignVerify {
    
    private final SecureRandom rnd;
    private final MessageDigest H;
    private final int L;
//    private final int N;

    /**
     * 
     * FIPS 186-3 (L, N) (1024, 160) (2048, 224) (2048, 256) (3072, 256) の4つ
     * @param H SHA-1, SHA-2
     * @param L 鍵長 512 から 1024 の 64 の倍数 から 2048, 3072
     * @param N FIPS 186-3 (L, N) (1024, 160) (2048, 224) (2048, 256) (3072, 256) の4つ ハッシュより短い?
     * 
     */
    public DSA(MessageDigest H, int L, int N) {
        try {
            rnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            throw new SecurityException(); // ない
        }
        this.H = H;
        this.L = L;
    }

    /**
     * 
     * ( L, N ) = (1024, 160) (2048, 224) (2048, 256) (3072, 256) の4種類 
     * @param pLen L 1024 bit 以上
     * @param qLen N 160 bit 以上
     * @deprecated まだ
     * @return 
     */
    @Deprecated
    public DSAPrivateKeySpec genSpec(int pLen, int qLen) {
        BigInteger p = BigInteger.probablePrime(pLen, rnd); // modulus
        BigInteger q = BigInteger.probablePrime(qLen, rnd); // divisor of (p-1)
        BigInteger pnl = p.subtract(BigInteger.ONE);
        
        int rLen = ( qLen + 7 ) & (~ 3);
        
        BigInteger g = BigInteger.valueOf(2);  // GF(p) の 1 < g < p
//        g.gcd(p).equals(BigInteger.ONE)
        while (!g.gcd(p).equals(BigInteger.ONE)) {
            g = g.add(BigInteger.ONE);
        }
        
        // 秘密鍵
        byte[] xsrc = new byte[(qLen + 8) / 8];
        
        rnd.nextBytes(xsrc);
        xsrc[0] = 0;
        BigInteger x = new BigInteger(xsrc).mod(q); // private key
        
//        return new DSAPrivateKeySpec(x, p, q, g);
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * DSA秘密鍵仕様から秘密鍵を構築.
     * @param spec DSA秘密鍵仕様
     * @return DSA秘密鍵
     */
    DSAPrivateKey prvKey(DSAPrivateKeySpec spec) {
        BigInteger x = spec.getX();
        BigInteger p = spec.getP();
        BigInteger q = spec.getQ();
        BigInteger g = spec.getG();
        return new DSAPrivateKey(x, p, q, g);
    }

    /**
     * 秘密鍵を公開鍵に変換.
     * @param pkey DSA秘密鍵
     * @return DSA公開鍵
     */
    DSAPublicKey pubKey(DSAPrivateKey pkey) {
        BigInteger x = pkey.getX();
        BigInteger p = pkey.getParams().getP(); // the prime
        BigInteger q = pkey.getParams().getQ(); // ths sub-prime
        BigInteger g = pkey.getParams().getG(); // the base
        
        BigInteger y = g.modPow(x, p); // public key
        DSAPublicKeySpec pubSpec = new DSAPublicKeySpec(y,p,q,g);
        return pubKey(pubSpec);
    }

    /**
     * 秘密鍵仕様から公開鍵.
     * @param spec 秘密鍵仕様
     * @return 
     */
    public DSAPublicKey pubKey(DSAPrivateKeySpec spec) {
        return pubKey(prvKey(spec));
    }
    
    public DSAPublicKey pubKey(DSAPublicKeySpec spec) {
        BigInteger y = spec.getY();
        BigInteger p = spec.getP();
        BigInteger q = spec.getQ();
        BigInteger g = spec.getG();
        return new DSAPublicKey(y, p, q, g);
    }

    @Override
    public int getKeyLength() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] sign() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}
