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
package net.siisise.security.key;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.siisise.iso.asn1.ASN1Object;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.security.key.RSAMultiPrivateKey.OtherPrimeInfo;

/**
 * RFC 8017 PKCS #1 3.2. RSA Private Key
 * FIPS 186-5
 * RSAKeyGen (Rivest-Shamir-Adleman).
 * RSA鍵 static系のまとめ
 * 鍵生成と検証ぐらいに使えるといい
 */
public class RSAKeyGen extends KeyPairGeneratorSpi {

    private int keysize;
    private SecureRandom srnd;

    @Override
    public void initialize(int keysize, SecureRandom random) {
        this.keysize = keysize;
        srnd = random;
    }

    /**
     * 最小構成の秘密鍵と公開鍵にする.
     * primeを持たない.
     * @return 最小構成の秘密鍵と公開鍵
     */
    @Override
    public KeyPair generateKeyPair() {
        RSAPrivateCrtKey fkey = generatePrivateKey(keysize, srnd, 2);
        return new KeyPair(fkey.getPublicKey(), fkey.getPrivateKey());
    }

    /**
     * 秘密鍵生成.
     * prime などを持つ.
     * @param len 鍵長(全体) 2048 以上かな 3072くらい
     * @return 全要素入り.
     * @throws java.security.NoSuchAlgorithmException
     */
    public static RSAPrivateCrtKey generatePrivateKey(int len) throws NoSuchAlgorithmException {
        return generatePrivateKey(len, SecureRandom.getInstanceStrong(), 2);
    }

    /**
     * 秘密鍵生成.
     * マルチプライムRSA 対応.
     * @param len 鍵長 (ビット)
     * @param u 2 または 3以上 まるちぷらいむ
     * @return 全要素入り.
     */
    static RSAPrivateCrtKey generatePrivateKey(int len, SecureRandom srnd, int u) {
        //RSAFullPrivateKey key = new RSAPrivateCrtKey();
        BigInteger lambda;
        BigInteger n; // modulus
        BigInteger e; // publicExponent

        int pbit = len % u;
//        do {
        srnd.nextBytes(new byte[srnd.nextInt() & 0x7ff]); // てきとー
        e = BigInteger.probablePrime(17, srnd); // e = 3 から n - 1 , GCD(e, \lambda(n)) = 1
//        } while ( key.publicExponent.compareTo(BigInteger.valueOf(2)) <= 0 );
        Set<BigInteger> primes = new HashSet<>();
        List<OtherPrimeInfo> pis = new ArrayList<>();
        do {
            lambda = BigInteger.ONE;
            n = BigInteger.ONE; // R_i と n 兼用
            primes.clear();
            pis.clear();

            for ( int i = 0; i < u; i++ ) { // i は RFCより1小さい
                OtherPrimeInfo pi = new OtherPrimeInfo();
                srnd.nextBytes(new byte[srnd.nextInt() & 0x7ff]); // てきとー
                pi.prime = BigInteger.probablePrime(len / u + (i < pbit ? 1 : 0), srnd); // r_i
                BigInteger p1e = pi.prime.subtract(BigInteger.ONE); // r_i - 1
                if ( primes.contains(pi.prime) || !gcd(e,p1e).equals(BigInteger.ONE) ) {
//                    System.out.println("重複素数 または r_i-1とeが素でない");
                    i--;
                    continue;
                }
                primes.add(pi.prime);
                pi.exponent = modInverse(e,p1e); // e * d_i = 1 (mod (r_i - 1))
                if ( i > 0 ) { // u > 2 と p
                    pi.coefficient = modInverse(n,pi.prime); // R_i * t_i = 1 (mod r_i)
                }
                lambda = lcm(lambda, p1e);
                pis.add(pi);
                n = n.multiply(pi.prime); // n : R_i = r_1 * r_2 * ... * r_(i - 1)
            }
        } while (!gcd(e,lambda).equals(BigInteger.ONE) || n.bitLength() < len); // 念のため

        OtherPrimeInfo oq = pis.remove(0); // coefficient 用に q p の順
        OtherPrimeInfo op = pis.remove(0);
        BigInteger d = modInverse(e,lambda); // e * d = 1 mod  lambda(n)    (p-1)(q-1) 
        BigInteger p = op.prime; // p
        BigInteger q = oq.prime; // q
        BigInteger dP = op.exponent; // e * dP = 1 (mod (p-1)) = d mod (p - 1)
        BigInteger dQ = oq.exponent; // e * dQ = 1 (mod (q-1)) = d mod (q - 1)
        BigInteger coefficient = op.coefficient; // qInv prime2(q) prime1(p) r_3 r_4 の並びを想定 3以降とは逆

        RSAPrivateCrtKey key;
        if ( u > 2 ) {
            key = new RSAMultiPrivateKey(n,e,d,p,q,dP,dQ,coefficient, pis);
            key.version = 1;
        } else {
            key = new RSAPrivateCrtKey(n,e,d,p,q,dP,dQ,coefficient);
            key.version = 0;
            if ( !validate(key)) {
                throw new SecurityException();
            }
        }

        return key;
    }
    
    /**
     * PKCS #1 DER 形式のデコード.
     * RFC 8017 A.1.2. RSA Private Key Syntax
     * @param src ASN.1 DER
     * @return RSA Crt Key
     * @throws IOException
     */
    public static RSAPrivateCrtKey decodeSecret1(byte[] src) throws IOException {
        SEQUENCE rsa = (SEQUENCE) ASN1Util.toASN1(src);
        BigInteger n = ((INTEGER)rsa.get(1)).getValue(); // n
        BigInteger e = ((INTEGER)rsa.get(2)).getValue(); // e
        BigInteger d = ((INTEGER)rsa.get(3)).getValue(); // d
        BigInteger p = ((INTEGER)rsa.get(4)).getValue(); // p
        BigInteger q = ((INTEGER)rsa.get(5)).getValue(); // q
        BigInteger dP = ((INTEGER)rsa.get(6)).getValue(); // d mod (p-1) : e * dP = 1 (mod (p-1))
        BigInteger dQ = ((INTEGER)rsa.get(7)).getValue(); // d mod (q-1) : e * dQ = 1 (mod (q-1))
        BigInteger c = ((INTEGER)rsa.get(8)).getValue();  // (inverse of q) mod p
        int v = ((INTEGER)rsa.get(0)).getValue().intValue();
        // オプションは未対応
        if ( v == 0 ) {
            RSAPrivateCrtKey pkey = new RSAPrivateCrtKey(n, e, d, p, q, dP, dQ, c);
            if ( !validate(pkey)) {
                throw new SecurityException("Invalid RSA Private Key");
            }
            return pkey;
        } else if ( v == 1 ) {
            List<RSAMultiPrivateKey.OtherPrimeInfo> op = new ArrayList<>();
            List<ASN1Object> apis = ((SEQUENCE) rsa.get(9)).getValue();
            for ( ASN1Object api : apis ) {
                SEQUENCE mp = (SEQUENCE) api;
                RSAMultiPrivateKey.OtherPrimeInfo pi = new RSAMultiPrivateKey.OtherPrimeInfo();
                pi.prime = ((INTEGER)mp.get(0)).getValue();
                pi.exponent = ((INTEGER)mp.get(1)).getValue();
                pi.coefficient = ((INTEGER)mp.get(2)).getValue();
                op.add(pi);
            }
            RSAMultiPrivateKey pkey = new RSAMultiPrivateKey(n, e, d, p, q, dP, dQ, c, op);
            return pkey;
        }
        throw new SecurityException("Invalid RSA Private Key");
    }
    
    public static SEQUENCE encodePublic8(RSAPublicKey pub) {
        return pub.getPKCS8ASN1();
    }

    /**
     * PKCS #1 を PKCS #8 でくるんだらしいもの
     * @param key
     * @return 
     */
    public static SEQUENCE encodePrivate8(RSAPrivateCrtKey key) {
        return key.getPKCS8PrivateKeyInfo().encodeASN1();
    }
    
    public static SEQUENCE encodePublic1(RSAPublicKey pub) {
        return pub.getPKCS1ASN1();
    }

    public static RSAPublicKey decodePublic1(byte[] asn) throws IOException {
        SEQUENCE seq = (SEQUENCE) ASN1Util.toASN1(asn);
        BigInteger n = ((INTEGER)seq.get(0)).getValue();
        BigInteger e = ((INTEGER)seq.get(1)).getValue();
        return new RSAPublicKey(n, e);
    }

    /**
     * PKCS #1 A.1.2. の構文出力
     * @param key
     * @return 
     */
    public static SEQUENCE encodePrivate1(RSAPrivateCrtKey key) {
        return key.getPKCS1ASN1();
    }

    private static final int PRIMECOUNT = 500;

    /**
     * version 0 のみ可.
     * @param key
     * @return 
     */
    public static boolean validate(RSAPrivateCrtKey key) {
        BigInteger ps = key.prime1.subtract(BigInteger.ONE);
        BigInteger qs = key.prime2.subtract(BigInteger.ONE);
        BigInteger lambda = lcm(ps,qs);
        return key.version == 0 && isPrime(key.prime1) && isPrime(key.prime2) &&
                key.modulus.equals(key.prime1.multiply(key.prime2)) &&
                key.prime1.isProbablePrime(PRIMECOUNT) && key.prime2.isProbablePrime(PRIMECOUNT) &&
                (!key.prime1.equals(key.prime2)) && gcd(key.publicExponent,lambda).equals(BigInteger.ONE) &&
                key.publicExponent.multiply(key.privateExponent).mod(lambda).equals(BigInteger.ONE) &&
                key.exponent1.equals(key.privateExponent.mod(ps)) && key.exponent2.equals(key.privateExponent.mod(qs)) &&
                key.coefficient.equals(key.prime2.modInverse(key.prime1));
    }

    /**
     * 確率的素数 probable prime 判定 (てきとー)
     * ToDo: Read FIPS 186-4 Appendix C 3.1
     *  a^(p-1) = 1 mod p 素数っぽい
     *  a.modPow(p,p) = a mod p
     *  a.modPow(p-1,p) = 1 mod p
     * 
     *  a^(e・dp)=a mod p 
     * 
     * @param p 素数候補
     * @return true たぶん素数 false 素数ではない 
     */
    static boolean isPrime(BigInteger p) {
        try {
            BigInteger b = p.subtract(BigInteger.ONE);
            SecureRandom srnd = SecureRandom.getInstanceStrong();
            for (int i = 0; i < PRIMECOUNT; i++ ) {
                BigInteger a = new BigInteger(srnd.generateSeed(p.bitCount() / 8 + 1)).abs().mod(p);
                if (!a.modPow(b, p).equals(BigInteger.ONE)) {
                    return false;
                }
            }
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(RSAKeyGen.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
            
        return true; // たぶん
    }

    /**
     * (非不整数の)最小公倍数.
     * RFC 8017 2. Notation GCD
     * @param a 非負整数
     * @param b 非負整数
     * @return 最小公倍数
     */
    static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.divide(gcd(a,b)).multiply(b);
    }

    /**
     * 最大公約数. RSA用なので0なし
     * ユークリッドの互除法
     * RFC 8017 2. Notation GCD
     * @param a 非負整数
     * @param b 非負整数
     * @return 最大公約数
     */
    static BigInteger gcd(BigInteger a, BigInteger b) {
        while ( !a.equals(BigInteger.ZERO)) {
            BigInteger m = b.mod(a);
            b = a;
            a = m;
        }
        return b;
    }
    
    /**
     * ax + by = gcd(a,b)
     * ax - 1 = qm
     * ax - qm = 1
     * @param a
     * @param m
     * @return 
     */
    static BigInteger modInverse(BigInteger a, BigInteger m) {
        if (BigInteger.ONE.equals(m)) {
            return BigInteger.ZERO;
        }

        BigInteger m0 = m;
        BigInteger y = BigInteger.ZERO;
        BigInteger x = BigInteger.ONE;

        while (a.compareTo(BigInteger.ONE) > 0) {
            BigInteger q = a.divide(m);  // q = a / m
            BigInteger t = m;
                           m = a.mod(m); // m = a % m
                               a = t;
                       t = y;
                           y = x.subtract(q.multiply(y));
                               x = t;
        }

        if (x.compareTo(BigInteger.ZERO) < 0) {
            x = x.add(m0);
        }
        return x;
    }
}
