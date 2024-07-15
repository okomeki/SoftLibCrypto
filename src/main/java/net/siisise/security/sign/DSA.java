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

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import net.siisise.bind.Rebind;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.SEQUENCE;
//import net.siisise.security.key.DSAPrivateKey;
//import net.siisise.security.key.DSAPublicKey;

/**
 * FIPS PUB 186-4
 * DOI https://doi.org/10.6028/NIST.FIPS.186-4
 * Section 4. DSA
 * DSA, ECDSA
 * RFC 6979
 * RFC 3279 
 * RFC 4055 ASN.1 module
 * RFC 5758 追加ハッシュ SHA-224, SHA-256
 * 
 * 入力
 *  k 乱数値 毎回必要
 * 
 */
public class DSA implements SignVerify {
    
    private DSAPrivateKey signKey;
    private DSAPublicKey verifyKey;

    private final SecureRandom rnd;
    private MessageDigest H;

    /**
     * 
     * FIPS 186-3 (L, N) (1024, 160) (2048, 224) (2048, 256) (3072, 256) の4つ
     * @param H SHA-1, SHA-2
     * 
     */
    public DSA(MessageDigest H) {
        try {
            rnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            throw new SecurityException(); // ない
        }
        this.H = H;
    }

    /**
     * 署名用鍵.
     *
     * @param skey 署名用鍵とハッシュ
     */
    public void init(DSAPrivateKey skey) {
        signKey = skey;
    }

    public void init(DSAPublicKey vkey) {
        verifyKey = vkey;
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
        return new net.siisise.security.key.DSAPrivateKey(x, p, q, g);
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
        return new net.siisise.security.key.DSAPublicKey(y, p, q, g);
    }

    @Override
    public int getKeyLength() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        H.update(src, offset, length);
    }

    private static BigInteger toNum(byte[] d) {
        return PKCS1.OS2IP(d);
    }

    /**
     * 0 &lt; x &lt; max
     *
     * @param max
     * @return
     */
    private BigInteger rnd1(BigInteger max) {
        int len = max.bitLength() + 8 / 8;
        byte[] bytes = new byte[len];
        rnd.nextBytes(bytes);
        bytes[0] &= 0x7f;
        return new BigInteger(bytes).mod(max.subtract(BigInteger.ONE)).add(BigInteger.ONE);
    }

    @Override
    public byte[] sign() {
        DSAParams params = signKey.getParams();
        BigInteger p = params.getP();
        BigInteger q = params.getQ();

        byte[] d = H.digest();
        int maxLen = q.bitLength() / 8;
        if (d.length > maxLen) {
            d = Arrays.copyOf(d, maxLen);
        }
        BigInteger z = toNum(d);

        BigInteger r;
        BigInteger s;
        do {
            BigInteger k;
            do {
                k = rnd1(q);
                r = params.getG().modPow(k, p).mod(q);
            } while (r.equals(BigInteger.ZERO));
            BigInteger zxr = z.add(signKey.getX().multiply(r));
            s = k.modInverse(q).multiply(zxr).mod(q);
        } while (s.equals(BigInteger.ZERO));
        List rs = new ArrayList();
        rs.add(r);
        rs.add(s);
        return new ASN1DERFormat().collectionFormat(rs);
    }

    /**
     *
     * @param sign
     * @return
     */
    @Override
    public boolean verify(byte[] sign) {
        try {
            SEQUENCE asn = (SEQUENCE) ASN1Util.toASN1(sign);
            List l = Rebind.valueOf(asn, List.class);

            DSAParams params = verifyKey.getParams();
            BigInteger p = params.getP();
            BigInteger q = params.getQ();

            byte[] d = H.digest();
            int maxLen = q.bitLength() / 8;
            if (d.length > maxLen) {
                d = Arrays.copyOf(d, maxLen);
            }
            BigInteger z = toNum(d);

            BigInteger r = (BigInteger) asn.get(0).getValue();
            BigInteger s = (BigInteger) asn.get(1).getValue();
            BigInteger w = s.modInverse(q);
            BigInteger u1 = z.multiply(w).mod(q);
            BigInteger u2 = r.multiply(w).mod(q);
            // v = (((g)^u1(y)^u2) mod p) mod q
            BigInteger v = params.getG().modPow(u1, p).multiply(verifyKey.getY().modPow(u2, p)).mod(p).mod( q);
            return v.equals(r);
        } catch (IOException ex) {
            return false;
        }
    }
}
