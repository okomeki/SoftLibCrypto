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
import net.siisise.iso.asn1.ASN1Object;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.security.key.RSAFullPrivateKey.OtherPrimeInfo;

/**
 * RFC 8017 PKCS #1 3.2. RSA Private Key
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
        RSAFullPrivateKey fkey = generatePrivateKey(keysize, srnd, 2);
        return new KeyPair(fkey.getPublicKey(), fkey.getPrivateKey());
    }

    /**
     * 秘密鍵生成.
     * prime などを持つ.
     * @param len 鍵長(全体) 2048 以上かな 3072くらい
     * @return 全要素入り.
     * @throws java.security.NoSuchAlgorithmException
     */
    public static RSAFullPrivateKey generatePrivateKey(int len) throws NoSuchAlgorithmException {
        return generatePrivateKey(len, SecureRandom.getInstanceStrong(), 2);
    }

    /**
     * 秘密鍵生成.
     * マルチプライムRSA 対応.
     * @param len 鍵長 (ビット)
     * @param u 2 または 3以上 まるちぷらいむ
     * @return 全要素入り.
     */
    static RSAFullPrivateKey generatePrivateKey(int len, SecureRandom srnd, int u) {
        RSAFullPrivateKey key = new RSAFullPrivateKey();
        BigInteger lambda;
       
        int pbit = len % u;
//        do {
        srnd.nextBytes(new byte[srnd.nextInt() & 0x7ff]); // てきとー
        key.publicExponent = BigInteger.probablePrime(17, srnd); // e = 3 から n - 1 , GCD(e, \lambda(n)) = 1
//        } while ( key.publicExponent.compareTo(BigInteger.valueOf(2)) <= 0 );
        Set<BigInteger> primes = new HashSet<>();
        List<OtherPrimeInfo> pis = new ArrayList<>();
        do {
            lambda = BigInteger.ONE;
            key.modulus = BigInteger.ONE; // R_i と n 兼用
            primes.clear();
            pis.clear();

            for ( int i = 0; i < u; i++ ) { // i は RFCより1小さい
                OtherPrimeInfo pi = new OtherPrimeInfo();
                srnd.nextBytes(new byte[srnd.nextInt() & 0x7ff]); // てきとー
                pi.prime = BigInteger.probablePrime(len / u + (i < pbit ? 1 : 0), srnd); // r_i
                BigInteger p1e = pi.prime.subtract(BigInteger.ONE); // r_i - 1
                if ( primes.contains(pi.prime) || !gcd(key.publicExponent,p1e).equals(BigInteger.ONE) ) {
                    System.out.println("重複素数 または r_i-1とeが素でない");
                    i--;
                    continue;
                }
                primes.add(pi.prime);
                pi.exponent = key.publicExponent.modInverse(p1e); // e * d_i = 1 (mod (r_i - 1))
                if ( i > 0 ) { // u > 2 と p
                    pi.coefficient = key.modulus.modInverse(pi.prime); // R_i * t_i = 1 (mod r_i)
                }
                lambda = lcm(lambda, p1e);
                pis.add(pi);
                key.modulus = key.modulus.multiply(pi.prime); // n : R_i = r_1 * r_2 * ... * r_(i - 1)
            }
            
        } while (!gcd(key.publicExponent,lambda).equals(BigInteger.ONE) || key.modulus.bitLength() < len); // 念のため

        OtherPrimeInfo q = pis.remove(0); // coefficient 用に q p の順
        OtherPrimeInfo p = pis.remove(0);
        key.privateExponent = key.publicExponent.modInverse(lambda); // e * d = 1 mod  lambda(n)    (p-1)(q-1) 
        key.prime1 = p.prime; // p
        key.prime2 = q.prime; // q
        key.exponent1 = p.exponent; // e * dP = 1 (mod (p-1))
        key.exponent2 = q.exponent; // e * dQ = 1 (mod (q-1))
        key.coefficient = p.coefficient; // qInv prime2(q) prime1(p) r_3 r_4 の並びを想定 3以降とは逆

        if ( u > 2 ) {
            key.version = 1;
            key.otherPrimeInfos = pis;
        } else {
            key.version = 0;
            if ( !validate(key)) {
                throw new SecurityException();
            }
        }

        return key;
    }
    
    /**
     *
     * @param src
     * @return
     * @throws IOException
     */
    public static RSAFullPrivateKey decodeSecret1(byte[] src) throws IOException {
        SEQUENCE rsa = (SEQUENCE) ASN1Util.toASN1(src);
        RSAFullPrivateKey pkey = new RSAFullPrivateKey();
        pkey.version = ((INTEGER)rsa.get(0)).getValue().intValue();
        pkey.modulus = ((INTEGER)rsa.get(1)).getValue(); // n
        pkey.publicExponent = ((INTEGER)rsa.get(2)).getValue(); // e
        pkey.privateExponent = ((INTEGER)rsa.get(3)).getValue(); // d
        pkey.prime1 = ((INTEGER)rsa.get(4)).getValue(); // p
        pkey.prime2 = ((INTEGER)rsa.get(5)).getValue(); // q
        pkey.exponent1 = ((INTEGER)rsa.get(6)).getValue(); // d mod (p-1) : e * dP = 1 (mod (p-1))
        pkey.exponent2 = ((INTEGER)rsa.get(7)).getValue(); // d mod (q-1) : e * dQ = 1 (mod (q-1))
        pkey.coefficient = ((INTEGER)rsa.get(8)).getValue(); // (inverse of q) mod p
        // オプションは未対応
        if ( pkey.version > 0 ) {
            pkey.otherPrimeInfos = new ArrayList<>();
            List<ASN1Object> apis = ((SEQUENCE) rsa.get(9)).getValue();
            for ( ASN1Object api : apis ) {
                SEQUENCE p = (SEQUENCE) api;
                RSAFullPrivateKey.OtherPrimeInfo pi = new RSAFullPrivateKey.OtherPrimeInfo();
                pi.prime = ((INTEGER)p.get(0)).getValue();
                pi.exponent = ((INTEGER)p.get(1)).getValue();
                pi.coefficient = ((INTEGER)p.get(2)).getValue();
                pkey.otherPrimeInfos.add(pi);
            }
        }
        if ( !validate(pkey)) {
            throw new SecurityException("Invalid RSA Private Key");
        }
        return pkey;
    }
    
    /**
     * PKCS #1 を PKCS #8 でくるんだらしいもの
     * @param key
     * @return 
     */
    public static SEQUENCE encodeSecret8(RSAFullPrivateKey key) {
        SEQUENCE s = new SEQUENCE();
        s.add(new INTEGER(0));
        SEQUENCE ids = new SEQUENCE();
        ids.add(new OBJECTIDENTIFIER("1.2.840.113549.1.1.1"));
        ids.add(new NULL());
        s.add(ids);
        s.add(new OCTETSTRING(encodeSecret1(key).encodeAll()));
        return s;
    }
    
    /**
     * PKCS #1 A.1.2. の構文出力
     * @param key
     * @return 
     */
    public static SEQUENCE encodeSecret1(RSAFullPrivateKey key) {
        SEQUENCE prv = new SEQUENCE(); // PKCS #1 の定義の範囲
        prv.add(new INTEGER(key.version));
        prv.add(new INTEGER(key.modulus));
        prv.add(new INTEGER(key.publicExponent));
        prv.add(new INTEGER(key.privateExponent));
        prv.add(new INTEGER(key.prime1));
        prv.add(new INTEGER(key.prime2));
        prv.add(new INTEGER(key.exponent1));
        prv.add(new INTEGER(key.exponent2));
        prv.add(new INTEGER(key.coefficient));
        if ( key.version > 0 ) {
            SEQUENCE ots = new SEQUENCE();
            for ( OtherPrimeInfo pi : key.otherPrimeInfos ) {
                SEQUENCE dpi = new SEQUENCE();
                dpi.add(new INTEGER(pi.prime));
                dpi.add(new INTEGER(pi.exponent));
                dpi.add(new INTEGER(pi.coefficient));
                ots.add(dpi);
            }
            prv.add(ots);
        }
        return prv;
    }

    /**
     * version 0 のみ可.
     * @param key
     * @return 
     */
    public static boolean validate(RSAFullPrivateKey key) {
        BigInteger ps = key.prime1.subtract(BigInteger.ONE);
        BigInteger qs = key.prime2.subtract(BigInteger.ONE);
        BigInteger l = lcm(ps,qs);
        return key.version == 0 && key.modulus.equals(key.prime1.multiply(key.prime2)) &&
                key.prime1.isProbablePrime(100) && key.prime2.isProbablePrime(100) &&
                (!key.prime1.equals(key.prime2)) && gcd(key.publicExponent,l).equals(BigInteger.ONE) &&
                key.publicExponent.multiply(key.privateExponent).mod(l).equals(BigInteger.ONE) &&
                key.exponent1.equals(key.privateExponent.mod(ps)) && key.exponent2.equals(key.privateExponent.mod(qs)) &&
                key.coefficient.equals(key.prime2.modInverse(key.prime1));
    }

    /**
     * 素数判定 (てきとー)
     * ToDo: Read FIPS 186-4 Appendix C 3.1
     * a^(m-1) = a mod m 素数っぽい
     * a.modPow(m-1,m) = a mod m
     * 
     * a^(e・dp)=a mod p 
     * 
     * @param m
     * @return
     * @throws NoSuchAlgorithmException 
     */
/*
    static boolean isPrime(BigInteger m) throws NoSuchAlgorithmException {
        BigInteger b = m.subtract(BigInteger.ONE);
        SecureRandom r = SecureRandom.getInstanceStrong();
        for (int i = 10; i < 2000; i++ ) {
            BigInteger a = new BigInteger(r.generateSeed(m.bitCount() / 8 + 1)).mod(m);
            if (!a.modPow(b, m).equals(a)) {
                return false;
            }
        }
        
        return true; // たぶん
    }
*/  

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
}
