/*
 * Copyright 2026 okome.
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
package net.siisise.security.math;

import java.math.BigInteger;

/**
 * The Finite Field 有限体
 * ガロア体 BigInteger な GF F_2^m.
 * order を個別に指定できる
 */
public class BIGF {

    /**
     * 多項式. f(n)
     */
    BigInteger p;
    /** 位数 - 1 */
    BigInteger io;
    /**
     * シフト量.
     * pのビット数 - 1
     */
    int plen;

    /**
     * ガロア拡大体をpだけで指定する.
     * order = 2^m - 1, inv には更に-1 ぐらいで計算する
     * @param p 多項式
     */
    public BIGF(BigInteger p) {
        this.p = p;
        plen = p.bitLength() - 1;
        this.io = BigInteger.ONE.shiftLeft(plen).subtract(BigInteger.TWO);
    }

    /**
     * 加算減産.
     *
     * @param a
     * @param b ...
     * @return a + b...
     */
    public BigInteger add(BigInteger a, BigInteger... b) {
        for (BigInteger b1 : b) {
            a = a.xor(b1);
        }
        return a;
    }

    /**
     * 乗算.
     *
     * @param a
     * @param b
     * @return ab
     */
    public BigInteger mul(BigInteger a, BigInteger b) {
        int blen = b.bitLength();
        BigInteger r = BigInteger.ZERO;
        for (int i = 0; i < blen; i++) {
            if (b.testBit(i)) {
                r = r.xor(a);
            }
            a = x(a);
        }
        return r;
    }

    /**
     * 逆数.
     * aa^-1 = 1 のような
     *
     * @param a
     * @return
     */
    public BigInteger inv(BigInteger a) {
        return pow(a, io);
    }

    /**
     * 逆数に使用する
     *
     * @param a
     * @param n
     * @return a^n
     */
    public BigInteger pow(BigInteger a, BigInteger n) {
        BigInteger sum = BigInteger.ONE;
        if (a.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        }
        if (n.compareTo(BigInteger.ONE) <= 0) {
            return a;
        }
        int z = n.bitLength();
        for (int i = 0; i < z; i++) {
            if (n.testBit(i)) {
                sum = mul(sum, a);
            }
            a = mul(a, a);
        }
        return sum;
    }

    /**
     * shiftLeft.
     *
     * @param a
     * @return a*2
     */
    public BigInteger x(BigInteger a) {
        a = a.shiftLeft(1);
        if (a.testBit(plen)) {
            a = a.xor(p);
        }
        return a;
    }

    /**
     * shiftRight.
     *
     * @param a
     * @return a/2
     */
    public BigInteger r(BigInteger a) {
        if (a.testBit(0)) {
            a = a.xor(p);
        }
        a = a.shiftRight(1);
        return a;
    }

}
