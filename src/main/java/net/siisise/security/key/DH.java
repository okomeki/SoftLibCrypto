/*
 * Copyright 2023 okome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain prv copy of the License at
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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * DHの基本形.
 * RSA とだいたい同じ
 * 
 * RFC 2631 などで拡張してあったり
 * 
 * P 大きな素数
 * g 種
 * xaとxbは秘密
 * yaとybは公開鍵
 * 
 * ya = g^xa mod P
 * yb = g^xb mod P
 * 
 * ZZ = ya^xb mod P
 * ZZ = yb^xa mod P
 * 
 * ZZ = g^(xa * xb) mod P
 * 
 * e^ab mod P
 */
public class DH {
    static SecureRandom srnd;
    
    static {
        try {
            srnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(DH.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    /**
     * 共通の要素を生成
     * @param plen 素数のビット長
     * @param glen 自然数のビット長っぽいもの
     * @return DH
     */
    public static DH genPublic(int plen, int glen) {
        BigInteger p = BigInteger.probablePrime(plen, srnd);
        BigInteger g = BigInteger.probablePrime(glen, srnd); // 仮に素数
        return new DH(p, g);
    }
    
    public static DH genSSHDH() {
        throw new UnsupportedOperationException();
//        return new DH(null,BigInteger.valueOf(2));
    }
    
    // 公開 素数
    BigInteger p;
    // 自然数?
    BigInteger g;
    // 秘密
    BigInteger prv;

    /**
     * 
     * @param p 素数
     * @param g 2 から p より小さい自然数
     */
    public DH(BigInteger p, BigInteger g) {
        this.p = p;
        this.g = g;
    }
    
    /**
     * RFC 2631用
     * g = h^(p-1 / q) mod h ?
     * @param p 大きな素数
     * @param q 大きな素数
     * @param h 1 &lt; h &lt; p-1内の任意の整数
     */
    public DH(BigInteger p, BigInteger q, BigInteger h) {
        h = h.mod(p);
        if ( h.compareTo(BigInteger.ONE) <= 0 ) {
            throw new IllegalStateException();
        }
        g = h.modPow(p.subtract(BigInteger.ONE).divide(q), h);
//        j = 
    }

    /**
     * 素数
     * @return  
     */
    public BigInteger getP() {
        return p;
    }
    
    public void setP(BigInteger p) {
        this.p = p;
    }
    
    public BigInteger getG() {
        return g;
    }
    
    public void setG(BigInteger g) {
        this.g = g;
    }

    /**
     * 中間鍵の出力.
     * @param bitlen 長さ
     * @return 中間鍵
     */
    public BigInteger genMiddle(int bitlen) {
        byte[] sbit = new byte[(bitlen+8)/8];
        srnd.nextBytes(sbit);
        sbit[0] &= 0x7f;
        prv = new BigInteger(sbit).mod(p);
        return g.modPow(prv, p);
    }
    
    /**
     * 共通鍵の取得.
     * @param middle 中間鍵
     * @return 共通鍵 common key
     */
    public BigInteger genZZKey(BigInteger middle) {
        return middle.modPow(prv, p);
    }
    
    
    boolean publicKeyValidation() {
        throw new UnsupportedOperationException();
    }
    
}
