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
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.digest.SHA1;

/**
 * DSAのDomainとx y 鍵生成.
 * FIPS PUB 186-4 DSS Section 4
 * 
 */
public class DSAKeyGen {
    
    static class LNPair {
        final int L;
        final int N;
        
        LNPair(int l, int n) {
            L = l;
            N = n;
        }
        
        boolean equals( int l, int n) {
            return (L == l) && (N == n);
        }
        
        @Override
        public boolean equals(Object o) {
            if ( o instanceof LNPair ) {
                return ((LNPair)o).L == L && ((LNPair)o).N == N;
            }
            return false;
        }
    }

    /**
     * FIPS PUB 186-4 で指定可能なのは4種類のみ.
     */
    public static final LNPair LN1016 = new LNPair(1024, 160);
    public static final LNPair LN2022 = new LNPair(2048, 224);
    public static final LNPair LN2025 = new LNPair(2048, 256);
    public static final LNPair LN3025 = new LNPair(3072, 256);
    
    
    /**
     * ひととおりDSAで使える秘密鍵を生成する。
     * @return 新規の秘密鍵
     */
    DSAPrivateKey gen(LNPair lp) {
        DSADomain domain = genDomain(lp);
        return genPrivateKey(domain);
    }

    /**
     * DSAのDomain に x を加えて秘密鍵を生成する。
     * SSH などは固定 domainがあるらしい。
     * @param domain
     * @return 
     */
    DSAPrivateKey genPrivateKey(DSADomain domain) {
        throw new java.lang.UnsupportedOperationException("まだない");
    }
    
    /**
     * 
     * @return ランダムなようなそうでないような.
     */
    BigInteger genK() {
        throw new java.lang.UnsupportedOperationException("まだない");
    }
    
    /**
     * DSA の Domain 要素を生成するよ。
     * 
     * FIPS 186-4
     * 4.3.1
     * 付録 A.1 p, q の生成
     * 
     * p, q, g
     * 
     * @return DSADomain
     */
    DSADomain genDomain(LNPair ln) {
        
        BigInteger p;
        BigInteger q;
        
        BigInteger g;
        
        throw new java.lang.UnsupportedOperationException("まだない");
    }
    
    private DSADomain a1(LNPair ln) {
        throw new java.lang.UnsupportedOperationException();
    }
    
    private DSADomain a11(LNPair ln) {
        throw new java.lang.UnsupportedOperationException();
    }
    
    /**
     * SHA-1 を使った古い方法 の検証.
     * L 1024 N 160 相当.
     * @param ln
     * @return true VALID / false INVALID
     * @deprecated 古いものの検証用
     */
    private boolean a111(BigInteger p, BigInteger q, BigInteger domainParameterSeed, int counter) {
        if ( p.bitLength() != 1024 || q.bitLength() != 160 ) return false; // 1
        if ( counter > 4095 ) return false; // 2
        int seedlen = domainParameterSeed.bitLength(); // 3
        if ( seedlen < 160 ) return false; // 4
        // 5
        byte[] seed = toBin(domainParameterSeed);
        SHA1 sha = new SHA1();
        byte[] shaSeed = sha.digest(seed);
        Bin.inc(seed);
        byte[] plusSeed = sha.digest(seed);
        Bin.xorl(shaSeed, plusSeed);
        shaSeed[0] |= 0x80; // 6
        shaSeed[shaSeed.length - 1] |= 1;
        if ( !testC3(toNum(shaSeed))) return false; // 7
        int offset = 2; // 8
        //byte[][] v = new byte[6][];
        int i;
        BigInteger computed_p = null;
        for ( i = 0; i <= counter; i++ ) {
            Packet v = new PacketA();
            for ( int j = 0; j <= 6; j++ ) {
                v.backWrite( sha.digest(toBin(domainParameterSeed.add(BigInteger.valueOf(offset + j)))));
            }
            byte[] W = new byte[128]; // 1024 / 8
            v.backRead(W);
            W[0] |= 0x80;
            BigInteger X = toNum(W);
            BigInteger c = X.mod(q.shiftLeft(1));
            computed_p = X.subtract(c).add(BigInteger.ONE);
            if ( computed_p.compareTo(BigInteger.ONE.shiftLeft(1023)) >= 0 ) {
                if ( testC3(computed_p) ) { // 9.7
                    break;
                }
            }
            offset += 7;
        
        }
        // 10
        return ( i == counter &&  p.equals(computed_p) && testC3(computed_p));
    }

    /**
     * バイト列変換.
     * ToDo: 仮
     * @param num 数値
     * @return バイト列
     */
    byte[] toBin(BigInteger num) {
        return PKCS1.I2OSP(num, (num.bitLength() + 7) / 8);
    }
    
    BigInteger toNum(byte[] bin) {
        return PKCS1.OS2IP(bin);
    }
    
    /**
     * A.1.1.2 確率的手法
     * @param ln
     * @return 
     */
    private DSADomain a112(LNPair ln, int seedlen) {
        throw new java.lang.UnsupportedOperationException();
    }
    
    /**
     * A.1.1.3
     * A.1.1.2 の検証
     * @param d
     * @return 
     */
    private boolean a113valid(DSADomain d) {
        throw new java.lang.UnsupportedOperationException();
        
    }
    
    boolean testC3(BigInteger n) {
        throw new java.lang.UnsupportedOperationException();
    }
    
}
