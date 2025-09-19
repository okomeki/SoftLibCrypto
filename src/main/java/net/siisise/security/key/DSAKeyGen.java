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
package net.siisise.security.key;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.digest.SHA1;
import net.siisise.security.digest.SHA224;
import net.siisise.security.digest.SHA256;
import net.siisise.security.digest.SHA512256;

/**
 * DSAのDomainとx y 鍵生成.
 * FIPS PUB 186-4 DSS Section 4
 *
 */
public class DSAKeyGen {

    public static class LNPair {

        // 素数 p の希望の長さ bit
        final int L;
        // 素数 q の希望の長さ bit
        final int N;
        
        // 仮
        final MessageDigest H;

        LNPair(int l, int n, MessageDigest h) {
            L = l;
            N = n;
            H = h;
        }

        boolean equals(int l, int n) {
            return (L == l) && (N == n);
        }

        @Override
        public boolean equals(Object o) {
            if (o instanceof LNPair) {
                return ((LNPair) o).L == L && ((LNPair) o).N == N;
            }
            return false;
        }
    }

    /**
     * FIPS PUB 186-4 4.2.で指定可能なのは4種類のみ.
     */
    public static final LNPair LN1016 = new LNPair(1024, 160, new SHA1());
    public static final LNPair LN2022 = new LNPair(2048, 224, new SHA224());
    public static final LNPair LN2025 = new LNPair(2048, 256, new SHA256());
    public static final LNPair LN3025 = new LNPair(3072, 256, new SHA512256());
    
    private SecureRandom srnd;

    private final MessageDigest md;
    // 仮
    private final int index;

    /**
     * 初期仮.
     * 
     * @param md 鍵の種類により変更が必要かも
     */
    public DSAKeyGen(MessageDigest md) {
        this.md = md;
        index = 7;
        try {
            srnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
    
    public DSAKeyGen() {
        this(new SHA1());
    }

    /**
     * ひととおりDSAで使える秘密鍵を生成する。
     *
     * @param lp domainの種類
     * @return 新規の秘密鍵
     */
    public DSAPrivateKey gen(LNPair lp) {
        DSADomain domain = genDomain(lp);
        return genPrivateKey(domain);
    }

    /**
     * DSAのDomain に x を加えて秘密鍵を生成する。
     * SSH などは固定 domainがあるらしい。
     *
     * @param domain
     * @return
     */
    DSAPrivateKey genPrivateKey(DSADomain domain) {
        BigInteger x = genK(domain.getQ());
        return new DSAPrivateKey(x, domain);
    }

    public DSAPrivateKey toPrivateKey(DSAPrivateKeySpec spec) {
        return new DSAPrivateKey(spec.getX(), spec.getP(), spec.getQ(), spec.getG());
    }

    public DSAPublicKey toPrivateKey(DSAPublicKeySpec spec) {
        return new DSAPublicKey(spec.getY(), spec.getP(), spec.getQ(), spec.getG());
    }
    
    /**
     * k または x の生成.
     * 0 &lt; k &lt; q
     * 
     * @return ランダムなようなそうでないような.
     */
    private BigInteger genK(BigInteger q) {
        byte[] kbin = new byte[(q.bitLength() + 8) / 8];
        srnd.nextBytes(kbin);
        kbin[0] &= 0x7f;
        BigInteger k = new BigInteger(kbin);
        return k.mod(q.subtract(BigInteger.ONE)).add(BigInteger.ONE);
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
     * @param ln 種類
     * @return DSADomain
     */
    public DSADomain genDomain(LNPair ln) {
        return a2gen(a1gen(ln));
    }

    /**
     * p q の生成
     *
     * @param ln
     * @return p と q, g は未定義
     */
    private DSADomain a1gen(LNPair ln) {
        return a11gen(ln);
    }

    /**
     * p q の生成
     *
     * @param ln
     * @return p と q, g は未定義
     */
    private DSADomain a11gen(LNPair ln) {
        return a112gen(ln, ln.H, 256);
    }

    /**
     * SHA-1 を使った古い方法 の検証.
     * L 1024 N 160 相当.
     *
     * @param p 1024bit
     * @param q 160bit
     * @param domainParameterSeed 160bit以上
     * @param counter 4095 まで
     * @return true VALID / false INVALID
     * @deprecated 古いものの検証用
     */
    @Deprecated
    private boolean a111validate(BigInteger p, BigInteger q, BigInteger domainParameterSeed, int counter) {
        if (p.bitLength() != 1024 || q.bitLength() != 160) {
            return false; // 1
        }
        if (counter > 4095) {
            return false; // 2
        }
        int seedlen = domainParameterSeed.bitLength(); // 3
        if (seedlen < 160) {
            return false; // 4
        }        // 5
        byte[] seed = toBin(domainParameterSeed);
        SHA1 sha = new SHA1();
        byte[] shaSeed = sha.digest(seed);
        seed = toBin(domainParameterSeed.add(BigInteger.ONE));
        byte[] plusSeed = sha.digest(seed);
        Bin.xorl(shaSeed, plusSeed); // comupted_q
        shaSeed[0] |= 0x80; // 6
        shaSeed[shaSeed.length - 1] |= 1;
        BigInteger computed_q = toNum(shaSeed);

        if ((!q.equals(computed_q)) || (!testC3(computed_q))) {
            return false; // 7
        }
        int offset = 2; // 8
        //byte[][] v = new byte[6][];
        int i;
        BigInteger computed_p = null;
        for (i = 0; i <= counter; i++) {
            PacketA v = new PacketA();
            for (int j = 0; j <= 6; j++) {
                v.backWrite(sha.digest(toBin(domainParameterSeed.add(BigInteger.valueOf(offset + j)))));
            }
            byte[] W = new byte[128]; // 1024 / 8
            v.backRead(W);
            W[0] |= 0x80;
            BigInteger X = toNum(W);
            BigInteger c = X.mod(q.shiftLeft(1));
            computed_p = X.subtract(c).add(BigInteger.ONE);
            if (computed_p.compareTo(BigInteger.ONE.shiftLeft(1023)) >= 0) {
                if (testC3(computed_p)) { // 9.7
                    break;
                }
            }
            offset += 7;

        }
        // 10
        return (i == counter && p.equals(computed_p) && testC3(computed_p));
    }

    /**
     * バイト列変換.
     * ToDo: 仮
     *
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
     * A.1.1.2 確率的手法.
     * pとqの生成 seedも保存する
     *
     * @param ln LとNの長さ
     * @param md
     * @param seedlen N以上の長さ
     * @return DSADomainFull の g 以外を埋めたもの
     */
    private DSADomainFull a112gen(LNPair ln, MessageDigest md, int seedlen) {
        // 1.
        if (!ln.equals(LN1016)
                && !ln.equals(LN2022)
                && !ln.equals(LN2025)
                && !ln.equals(LN3025)) {
            return null;
        }
        if (seedlen < ln.N) {
            return null;
        } // 2.
        int outlen = md.getDigestLength() * 8;
        int n = (ln.L + outlen - 1) / outlen - 1; // 3. L = p の bit長 n = MD繰り返し - 1 ?
        int b = ln.L - 1 - (n * outlen); // 4. b = 端数

        byte[] seed = new byte[(seedlen + 7) / 8];

        while (true) {
            BigInteger q;
            do {
                srnd.nextBytes(seed); // 5. ビットシーケンス
                byte[] U = md.digest(seed); // 6.
                U[0] |= 0x80; // 7. 指定ビット数、奇数にする
                U[U.length - 1] |= 0x01;
                q = toNum(U);
            } while (!testC3(q)); // 8. 素数テスト 9. 素数でない場合 5.へ

            BigInteger domain_parameter_seed = toNum(seed); // 5. の残り

            int offset = 1; // 10.
            for (int counter = 0; counter < ln.L * 4; counter++) { // 11.
                BigInteger cnt = domain_parameter_seed.add(BigInteger.valueOf(offset));
                PacketA V = new PacketA();
                for (int j = 0; j <= n; j++) {
                    // 11.1.
                    byte[] cb = toBin(cnt);
                    V.backWrite(md.digest(cb));
                    cnt = cnt.add(BigInteger.ONE);
                }
                byte[] W = new byte[(ln.L + 7) / 8];
                V.backRead(W); // 11.2
                W[0] |= 0x80; // 11.3
                BigInteger X = toNum(W);
                BigInteger c = X.mod(q.shiftLeft(1)); // 11.4
                BigInteger p = X.subtract(c).add(BigInteger.ONE); // 11.5
                if (p.bitLength() >= ln.L - 1) { // 11.6
                    if (testC3(p)) { // 11.7
                        return new DSADomainFull(p, q, BigInteger.ZERO, domain_parameter_seed, counter);
                    }
                }
                offset += n + 1;

            }
        }
    }

    /**
     * A.1.1.3
     * A.1.1.2 の検証
     *
     * @param d
     * @return
     */
    private boolean a113valid(DSADomain d) {
        throw new java.lang.UnsupportedOperationException();
    }

    /**
     * pqの生成 2.
     */
    private void a12() {
        throw new java.lang.UnsupportedOperationException();
    }

    /**
     * Generation of the Generator g
     *
     * @param d domain
     * @return g
     */
    private DSADomain a2gen(DSADomain d) {
        if (d instanceof DSADomainFull) {
            BigInteger g = a23gen((DSADomainFull) d, md, index);
            return new DSADomainFull(d.getP(), d.getQ(), g, ((DSADomainFull) d).getDomainParameterSeed(), ((DSADomainFull) d).getCounter());
        } else {
            BigInteger g;
            g = a21gen(d);
            return new DSADomain(d.getP(), d.getQ(), g);
        }
    }
    
    private boolean a2valid(DSADomain d) {
        if (d instanceof DSADomainFull) {
            return a24valid((DSADomainFull) d, md, index);
        }
        return a22valid(d);
    }

    /**
     * g生成. A.2.1. 古い方法
     */
    private BigInteger a21gen(DSADomain d) {
        BigInteger p = d.getP();
        BigInteger q = d.getQ();
        BigInteger e = p.subtract(BigInteger.ONE).divide(q); // 1.

        BigInteger g;
        do {
            BigInteger h;
            do {
                byte[] a = new byte[(p.bitLength() + 7) / 8];
                srnd.nextBytes(a);
                h = toNum(a).mod(p.subtract(BigInteger.ONE));
            } while (h.compareTo(BigInteger.ONE) < 0);
            g = h.modPow(e, p);
        } while (g.equals(BigInteger.ONE));
        return g;
    }

    boolean a22valid(DSADomain d) {
        BigInteger p = d.getP();
        BigInteger q = d.getQ();
        BigInteger g = d.getG();
        if (g.compareTo(BigInteger.ONE) <= 0 || g.compareTo(p) >= 0) {
            return false;
        }
        return g.modPow(q, p).equals(BigInteger.ONE);
    }
    
    /**
     * A.2.3.
     * 
     * @param d
     * @return 
     */
    private BigInteger a23gen(DSADomainFull d, MessageDigest md, int index) {
        if ( (index & 0xff) != index ) return null; // 1.
        BigInteger q = d.getQ();
//        int N = q.bitLength(); // 2.
        BigInteger p = d.getP();
        BigInteger e = (p.subtract(BigInteger.ONE).divide(q)); // 3.
        short count = 0; // 4.
        byte[] seed = toBin(d.getDomainParameterSeed());
        BigInteger g;
        do {
            count++; // 5.
            if ( count == 0) return null; // 6.
            md.update(seed); // 7.
            md.update("ggen".getBytes());
            md.update((byte) index);
            md.update((byte) (count >>> 8));
            md.update((byte) count);
            byte[] W = md.digest(); // 8.
            g = toNum(W).modPow(e, p);
        } while (g.compareTo(BigInteger.ONE) <= 0);
        return g;
    }
    
    private boolean a24valid(DSADomainFull d, MessageDigest md, int index) {
        BigInteger p = d.getP();
        BigInteger q = d.getQ();
        byte[] seed = toBin(d.getDomainParameterSeed());
        BigInteger g = d.getG();
        if ( (index & 0xff) != index ) return false; // 1.
        if (g.compareTo(BigInteger.ONE) <= 0 || g.compareTo(p) >= 0) return false;  // 2.
        if (!g.modPow(q, p).equals(BigInteger.ONE)) return false;
//        int N = q.bitLength(); // 4.
        BigInteger e = p.subtract(BigInteger.ONE).divide(q);
        int count = 0;
        BigInteger computed_g;
        do {
            count++;
            if ( count == 0) return false;
            md.update(seed);
            md.update("ggen".getBytes());
            md.update((byte) index);
            md.update((byte) (count >>> 8));
            md.update((byte) count);
            byte[] W = md.digest();
            computed_g = toNum(W).modPow(e, p);
        } while (computed_g.compareTo(BigInteger.ONE) <= 0);
        return computed_g.equals(g);
    }

    /**
     * 素数の確認.
     *
     * @param n
     * @return
     */
    boolean testC3(BigInteger n) {
        return n.isProbablePrime(100); // 仮
        //throw new java.lang.UnsupportedOperationException();
    }

}
