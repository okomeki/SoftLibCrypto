/*
 * Copyright 2024 okome.
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
import java.util.Arrays;
import net.siisise.io.PacketA;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.security.digest.SHA512;
import net.siisise.security.digest.SHAKE256;
import net.siisise.security.key.EdDSAPrivateKey;
import net.siisise.security.key.EdDSAPublicKey;

/**
 * RFC 8032 EdDSA nonce 確定的
 * 公開鍵 32byte 256bit
 * 秘密鍵
 * 署名 64byte 512bit
 */
public class EdDSA implements SignVerify {

    public static final OBJECTIDENTIFIER X25519 = new OBJECTIDENTIFIER("1.3.101.110");
    public static final OBJECTIDENTIFIER X448 = new OBJECTIDENTIFIER("1.3.101.111");
    public static final OBJECTIDENTIFIER Ed25519 = new OBJECTIDENTIFIER("1.3.101.112");
    public static final OBJECTIDENTIFIER Ed448 = new OBJECTIDENTIFIER("1.3.101.113");

    /**
     * Ed25519 32byte 256bit
     * Ed448
     */
    EdDSAPrivateKey pkey;
    EdDSAPublicKey pubKey;
    byte[] key;
    // ハッシュ後鍵
    byte[] hkey;
    BigInteger s;
    byte[] prefix;

    PacketA block = new PacketA();
    
    public static class Point {

        public BigInteger x;
        public BigInteger y;

        public Point(BigInteger sx, BigInteger sy) {
            x = sx;
            y = sy;
        }

        /**
         * 5.1.2. Encoding.
         * @param bit curve.b
         * @return 
         */
        public byte[] encXY(int bit) {
            byte[] code = new byte[bit / 8];
            byte[] by = y.toByteArray();
            int l = code.length - 1;
            for (int i = 0; i < by.length; i++) {
                code[l - i] = by[i];
            }
            code[code.length - 1] |= x.testBit(bit - 1) ? 0x80 : 0;
            return code;
        }
        
        /**
         * 5.1.3. Decoding.
         * @param code 5.1.2で符号化されたもの
         * @param curve
         */
        public static Point decXY(byte[] code, EllipticCurve curve) {
            // 1.
            byte[] by = rev(code);
            int x_0 = ((by[0] & 0x80) >>> 7) & 1;
            by[0] &= 0x7f;
            BigInteger y = new BigInteger(by); //new BigInteger(by);
            if (y.compareTo(curve.p) >= 0) {
                throw new IllegalStateException();
            }
            // 2.
            BigInteger THREE = BigInteger.valueOf(3);
            BigInteger FOUR = BigInteger.valueOf(4);
            BigInteger FIVE = BigInteger.valueOf(5);
            BigInteger EIGHT = BigInteger.valueOf(8);

            BigInteger yy = y.multiply(y); // y.modPow(BigInteger.TWO, curve.p);
            BigInteger u = yy.subtract(BigInteger.ONE);//.mod(curve.p);
            BigInteger v = curve.d.multiply(yy).add(BigInteger.ONE);//.mod(curve.p);
            //BigInteger uv = u.multiply(v).mod(curve.p);
            BigInteger urv = u.multiply(v.modInverse(curve.p));//.mod(curve.p);
            if (urv.equals(BigInteger.ZERO)) {
                if (x_0 != 0) {
                    throw new IllegalStateException();
                } else {
                    return new Point(BigInteger.ZERO, y);
                }
            }
            
            BigInteger x = urv.modPow(curve.p.add(THREE).divide(EIGHT), curve.p);
            BigInteger xx = x.multiply(x);
            if (!xx.subtract(urv).mod(curve.p).equals(BigInteger.ZERO)) {
                BigInteger m1 = BigInteger.TWO.modPow(curve.p.subtract(BigInteger.ONE).divide(FOUR), curve.p);
                x = x.multiply(m1).mod(curve.p);
                xx = x.multiply(x);
                if (!xx.subtract(urv).mod(curve.p).equals(BigInteger.ZERO)) {
                    throw new IllegalStateException();
                }
            }
            System.out.println(x);
            if ( x.testBit(0) != (x_0 == 1)) {
                
            }
            //BigInteger x = u.multiply(uv.modPow(curve.p.subtract(FIVE).divide(EIGHT), curve.p)).mod(curve.p);
            // 3.
            BigInteger vxx = x.modPow(BigInteger.TWO, curve.p).multiply(v);
            System.out.println(vxx);
            System.out.println(u);
            if (!vxx.equals(u)) {
                if (!vxx.equals(u.negate())) {
                    throw new IllegalStateException(vxx.toString() + " " + u.toString());
                } else {
                    x = x.multiply(BigInteger.TWO.modPow(curve.p.subtract(BigInteger.ONE).divide(FOUR),curve.p));
                }
            }
            // 4.
            if (x_0 == 1 && x.equals(BigInteger.ZERO)) {
                throw new IllegalStateException();
            }
//            int x0 = x.mod(BigInteger.TWO).intValue();
            int x0 = x.testBit(0) ? 1 : 0;
            if (x_0 != x0) {
                x = curve.p.subtract(x);
            }
            return new Point(x,y);
        }
    }

    /**
     * パラメータ. ECDSAと同じ? RFC 8032 3.のパラメータ
     */
    public static class EllipticCurve {
        public final OBJECTIDENTIFIER oid;

        // 1. GF(p) 奇数
        final BigInteger p;
        // 2. 鍵と署名のサイズの元 2^(b-1) > p
        public final int b;
        // 3. 有限体 GF(p)の要素のb-1ビットエンコーディング
        // ENC のことか?
        // 4. 暗号ハッシュ関数H 25519はSHA512 449はSHAKE EdDSA用 Curveとは別
        final MessageDigest H;
        // 5. 対数 c 2または3
        // c <= n < b 上位ビットから有効なビット数
        public final int c;
        // 6. c <= n < b
        public final int n;
        // 7. GF(p)の非正方形要素
        private final BigInteger d;
        // 8. GF(p)の非ゼロの正方形要素
        private final BigInteger a;
        // 9. B
        final Point B;
        // 10. 素数
        BigInteger L;
        // 11. prehash
//        MessageDigest PH;

//        byte[] SIG;
//        int phflag;
        
        EllipticCurve(OBJECTIDENTIFIER oid, BigInteger p, int b, int c, int n, int a, BigInteger d, Point B, MessageDigest H, BigInteger L) {
            this.oid = oid;
            this.p = p;
            this.b = b;
            this.c = c;
            this.n = n;
            this.a = BigInteger.valueOf(a);
            this.d = d;
            this.B = B;
            this.H = H;
            this.L = L;
        }

        /*
         * ハッシュの頭.
         *
         * @param x
         * @param y context
         * @return
         *
        byte[] dom(int x, byte[] y) {
            Packet dom = new PacketA();
            dom.write(SIG);
            dom.write(x);
            dom.write(y.length); // 32bit int
            dom.write(y);
            return dom.toByteArray();
        }
*/
        public byte[] digest(byte[] s) {
            H.reset();
            return H.digest(s);
        }

        /*
         * PH ぷりハッシュ計算.
         *
         * @param x message
         * @return hash
         */
        public byte[] PH(byte[] x) {
            return x;
        }


        public Point nE(BigInteger x) {
            return nE(x, B);
        }

        Point nE(BigInteger x, Point b) {
            return nE(x, new xPoint(b)).toPoint();
        }

        xPoint nE(BigInteger x, xPoint p) {
            xPoint r = new xPoint();
            int bl = x.bitLength();
            for (int i = 0; i < bl; i++) {
                if (x.testBit(i)) {
                    r = r.add(p);
                }
                p = p.x2();
            }
            return r;
        }
        
//        abstract xPoint xPoint(Point p);

        class xPoint {

            BigInteger X;
            BigInteger Y;
            BigInteger Z;
            BigInteger T;

            xPoint(Point p) {
                Z = BigInteger.ONE;
                X = p.x;
                Y = p.y;
                T = p.x.multiply(p.y);
            }

            xPoint() {
                X = BigInteger.ZERO;
                Y = BigInteger.ONE;
                Z = BigInteger.ONE;
                T = BigInteger.ZERO;
            }

            xPoint(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) {
                this.X = X;
                this.Y = Y;
                this.Z = Z;
                this.T = T;
            }

            Point toPoint() {
                BigInteger R = Z.modInverse(p);
                BigInteger x = X.multiply(R).mod(p);
                BigInteger y = Y.multiply(R).mod(p);
                return new Point(x, y);
            }

            xPoint add(xPoint b) {
                BigInteger A = Y.subtract(X).multiply(b.Y.subtract(b.X));
                BigInteger B = Y.add(X).multiply(b.Y.add(b.X));
                BigInteger C = T.multiply(BigInteger.TWO).multiply(d).multiply(b.T).mod(p);
                BigInteger D = Z.multiply(BigInteger.TWO).multiply(b.Z).mod(p);
                BigInteger E = B.subtract(A).mod(p);
                BigInteger F = D.subtract(C).mod(p);
                BigInteger G = D.add(C).mod(p);
                BigInteger H = B.add(A).mod(p);
                BigInteger X2 = E.multiply(F).mod(p);
                BigInteger Y2 = G.multiply(H).mod(p);
                BigInteger T2 = E.multiply(H).mod(p);
                BigInteger Z2 = F.multiply(G).mod(p);
                return new xPoint(X2, Y2, Z2, T2);
            }

            xPoint x2() {
                BigInteger A = X.modPow(BigInteger.TWO, p);
                BigInteger B = Y.modPow(BigInteger.TWO, p);
                BigInteger C = Z.modPow(BigInteger.TWO, p).multiply(BigInteger.TWO).mod(p);
                BigInteger H = A.add(B).mod(p);
                BigInteger E = H.subtract(X.add(Y).modPow(BigInteger.TWO, p));
                BigInteger G = A.subtract(B).mod(p);
                BigInteger F = C.add(G).mod(p);
                BigInteger X2 = E.multiply(F).mod(p);
                BigInteger Y2 = G.multiply(H).mod(p);
                BigInteger T2 = E.multiply(H).mod(p);
                BigInteger Z2 = F.multiply(G).mod(p);
                return new xPoint(X2, Y2, Z2, T2);
            }

        }
    }

    static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger P448 = BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224).subtract(BigInteger.ONE));
    static final BigInteger D25519 = new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555");
    static final BigInteger D448 = BigInteger.valueOf(-39081);
    static final Point B25519 = new Point(new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202"),
                new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960"));
    static final Point B448 = new Point(new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710"),
            new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660"));
    static final BigInteger L25519 = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    static final BigInteger L448 = BigInteger.ONE.shiftLeft(446).add(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));
            
//    static final byte[] SIGED25519 = "SigEd25519 no Ed25519 collisions".getBytes(StandardCharsets.ISO_8859_1);
//    static final byte[] SIGED448 = "SigEd448".getBytes(StandardCharsets.ISO_8859_1);

    /**
     * RFC 7748 Ed25519 暗号強度 128bit 鍵長 256bit DJB作?
     */
    public static class EdWards25519 extends EllipticCurve {
        public EdWards25519() {
            super(Ed25519, P25519, 256, 3, 254, -1, D25519, B25519, new SHA512(),L25519);
        }
    }

    /**
     * RFC 7748 Ed448 暗号強度 224bit 鍵長 448bit DJB作?
     */
    public static class EdWards448 extends EllipticCurve {
        public EdWards448() {
            super( Ed448, P448, 456, 2, 447, 1, D448, B448, new SHAKE256(114*8),L448); // 448 + 8
        }
    }

    public static EdWards25519 init25519() {
        return new EdWards25519();
    }

    public EdWards448 init448() {
        return new EdWards448();
    }

    public EdDSA() {
    }

    public EdDSA(EdDSAPrivateKey k) {
        pkey = k;
        preSign();
    }

    public EdDSA(EdDSAPublicKey pub) {
        pubKey = pub;
    }

    void preSign() {
        hkey = pkey.init();
        EdDSA.EllipticCurve curve = pkey.curve();
        int hlen = curve.b / 8;
        MessageDigest h = curve.H;
        h.reset();
        h.update(Arrays.copyOfRange(hkey, hlen, hkey.length));
    }

    /**
     * 秘密鍵長?
     *
     * @return 秘密鍵長(バイト)
     */
    @Override
    public int getKeyLength() {
        return pkey.curve().b / 8;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        if ( pkey != null) {
            pkey.curve().H.update(src, offset, length);
        }
        block.write(src, offset, length);
    }

    /**
     *
     * Little Endian 変換.
     *
     * @param src
     * @return
     */
    byte[] itob(BigInteger src, int len) {
        byte[] code = src.toByteArray();
        byte[] dst = new byte[len];
        if (code[0] < 0 && dst.length > code.length) {
            Arrays.fill(dst, code.length, dst.length, (byte) 0xff);
        }
        int offset = 0;
        for (int i = code.length - 1; i >= 0; i--) {
            dst[offset++] = code[i];
        }
        return dst;
    }

    /**
     * Little Endian (仮)
     *
     * @param src LE INTEGER
     * @return BigInteger
     */
    static BigInteger btoi(byte[] src) {
        int len = ((src[src.length - 1] & 0x80) == 0) ? src.length : (src.length + 1);
        byte[] code = new byte[len];
        int offset = len - 1;
        for (int i = 0; i < src.length; i++) {
            code[offset--] = src[i];
        }
        return new BigInteger(code);
    }

    public static byte[] rev(byte[] s) {
        int r = s.length;
        byte[] rev = new byte[r];
        for (int i = 0; i < s.length; i++) {
            rev[i] = s[--r];
        }
        return rev;
    }

    /**
     * 秘密鍵.
     * RFC 8410 CurvePrivateKey の形式
     * PKCS #8 の privateKey OCTETSTRING
     *
     * @param curve 曲線
     * @return OCTETSTRING な形式?
     */
    public byte[] genPrvKey(EllipticCurve curve) {
        byte[] rnd = new byte[curve.b / 8]; // ?
        SecureRandom srnd;
        try {
            srnd = SecureRandom.getInstanceStrong();
            srnd.nextBytes(rnd);
            key = rnd.clone();
            pkey = new EdDSAPrivateKey(curve,key);
            preSign();
            OCTETSTRING oct = new OCTETSTRING(rnd);
            ASN1DERFormat der = new ASN1DERFormat();
            return oct.rebind(der);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    /**
     * 5.1.5. 鍵の生成
     * 秘密鍵は乱数
     * スカラー s
     * 公開鍵
     *
     * @return 公開鍵
     */
    public byte[] genPubKey() {
        return pkey.getPublicKey().getA();
    }

    /**
     * RFC 8032 5.1.6. Sign
     */
    @Override
    public byte[] sign() {
        EllipticCurve curve = pkey.curve();
        BigInteger r = btoi(curve.H.digest());
        // r を　L で約分 (省略可?)
        r = r.mod(curve.L);
        Point R = curve.nE(r);
        curve.H.update(R.encXY(curve.b));
        curve.H.update(pkey.getA());
        byte[] phM = block.toByteArray(); //curve.PH(); // PH(M)
        byte[] k = curve.H.digest(phM);
        BigInteger S = r.add(btoi(k).multiply(pkey.gets())).mod(curve.L);
        PacketA d = new PacketA();
        d.write(R.encXY(curve.b));
        d.write(itob(S, curve.b / 8));
        
        preSign();
        return d.toByteArray();
    }
    
    /**
     *
     * @param sign
     * @return
     */
    @Override
    public boolean verify(byte[] sign) {
        EdWards25519 curve = new EdWards25519();
        int hlen = curve.b / 8;
        byte[] R = Arrays.copyOfRange(sign, 0, hlen);
        byte[] S = Arrays.copyOfRange(sign, hlen, hlen * 2);
        byte[] A = pubKey.getA();
        byte[] phM = block.toByteArray();
        curve.H.reset();
        curve.H.update(R);
        curve.H.update(A);
        byte[] h = curve.H.digest(phM);
        Point SB = curve.nE(btoi(S));
        Point HA = curve.nE(btoi(h), Point.decXY(A, curve));
        byte[] NSB = SB.encXY(curve.b);
        byte[] NHA = HA.encXY(curve.b);

        return Arrays.compare(NSB, NHA) == 0;
    }
}
