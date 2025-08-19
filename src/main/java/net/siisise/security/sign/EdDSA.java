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
import net.siisise.lang.Bin;
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

    private static final BigInteger THREE = BigInteger.valueOf(3);
    private static final BigInteger FOUR = BigInteger.valueOf(4);
    private static final BigInteger FIVE = BigInteger.valueOf(5);
    private static final BigInteger EIGHT = BigInteger.valueOf(8);

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
            byte[] code = itob(y, bit/8);
            code[code.length - 1] |= x.testBit(0) ? 0x80 : 0;
            return code;
        }
        
        @Override
        public boolean equals(Object p) {
            if ( p instanceof Point ) {
                Point xp = (Point) p;
                return xp.x.equals(x) && xp.y.equals(y);
            }
            return false;
        }
    }

    /**
     * パラメータ. ECDSAと同じ? RFC 8032 3.のパラメータ
     */
    public abstract static class EllipticCurve {
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
        final BigInteger d;
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

        abstract public Point decXY(byte[] code);
        
        public Point nE(BigInteger x) {
            return nE(x, B);
        }

        Point nE(BigInteger x, Point b) {
            return nE(x, toxPoint(b)).toPoint();
        }
        
        abstract xPoint toxPoint(Point x);

        Point add(Point a, Point b) {
            return toxPoint(a).add(toxPoint(b)).toPoint();
        }

        abstract class xPoint {
            protected BigInteger X;
            protected BigInteger Y;
            protected BigInteger Z;

            Point toPoint() {
                BigInteger R = Z.modInverse(p);
                BigInteger x = X.multiply(R).mod(p);
                BigInteger y = Y.multiply(R).mod(p);
                return new Point(x, y);
            }
            
            abstract xPoint add(xPoint x);
            abstract xPoint x2();
        }
        
        abstract xPoint nE(BigInteger x, xPoint p);
        
        
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

        /**
         * 5.1.3. Decoding.
         * @param code 5.1.2で符号化されたもの
         * @return 復元Point
         */
        @Override
        public Point decXY(byte[] code) {
            // 1.
            byte[] by = rev(code);
            boolean x_0 = (by[0] & 0x80) != 0;
            by[0] &= 0x7f;
            BigInteger y = new BigInteger(by); //new BigInteger(by);
            if (y.compareTo(p) >= 0) {
                throw new IllegalStateException();
            }
            // 2.
            BigInteger yy = y.modPow(BigInteger.TWO, p); // y.modPow(BigInteger.TWO, curve.p);
            BigInteger u = sub(yy,BigInteger.ONE);
            BigInteger v = d.multiply(yy).add(BigInteger.ONE).mod(p);
            BigInteger uv = u.multiply(v).mod(p);
            BigInteger x = u.multiply(uv.modPow(p.divide(EIGHT), p)).mod(p);
            // 3.
            BigInteger vxx = v.multiply(x.modPow(BigInteger.TWO, p)).mod(p);
//            BigInteger x2 = u.multiply(v.modInverse(p)).mod(p);
//            BigInteger vxx = v.multiply(x2).mod(p);
            if ( !vxx.equals(u) ) {
                if (vxx.equals(p.subtract(u))) {
                    BigInteger z = BigInteger.TWO.modPow(p.divide(FOUR), p);
                    x = x.multiply(z).mod(p);
                } else {
                    throw new IllegalStateException();
                }
            }
            // 4.
            if ( x_0 && x.equals(BigInteger.ZERO)) {
                throw new IllegalStateException();
            }
            if (x.testBit(0) != x_0) {
                x = p.subtract(x);
            }
            return new Point(x,y);
        }
        
        @Override
        x25519Point toxPoint(Point x) {
            return new x25519Point(x);
        }

        @Override
        xPoint nE(BigInteger x, xPoint p) {
            x25519Point r = new x25519Point();
            int bl = x.bitLength();
            for (int i = 0; i < bl; i++) {
                if (x.testBit(i)) {
                    r = r.add(p);
                }
                p = p.x2();
            }
            return r;
        }

        BigInteger sub(BigInteger a, BigInteger b) {
            BigInteger s = a.subtract(b);
            if (s.compareTo(BigInteger.ZERO) < 0) {
                return p.add(s);
            }
            return s;
        }

//        @Override
//        Point add(Point a, Point b) {
//            return new x25519Point(a).add(new x25519Point(b)).toPoint();
//        }
        
        class x25519Point extends xPoint {

            BigInteger T;

            x25519Point(Point p) {
                Z = BigInteger.ONE;
                X = p.x;
                Y = p.y;
                T = p.x.multiply(p.y);
            }

            x25519Point() {
                X = BigInteger.ZERO;
                Y = BigInteger.ONE;
                Z = BigInteger.ONE;
                T = BigInteger.ZERO;
            }

            x25519Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) {
                this.X = X;
                this.Y = Y;
                this.Z = Z;
                this.T = T;
            }

            @Override
            x25519Point add(xPoint sb) {
                x25519Point b = (x25519Point) sb;
                BigInteger A = sub(Y, X).multiply(sub(b.Y,b.X)).mod(p);
                BigInteger B = Y.add(X).multiply(b.Y.add(b.X)).mod(p);
                BigInteger C = T.multiply(BigInteger.TWO).multiply(d).mod(p).multiply(b.T).mod(p);
                BigInteger D = Z.multiply(BigInteger.TWO).multiply(b.Z).mod(p);
                BigInteger E = sub(B,A);
                BigInteger F = sub(D,C);
                BigInteger G = D.add(C).mod(p);
                BigInteger H = B.add(A).mod(p);
                BigInteger X2 = E.multiply(F).mod(p);
                BigInteger Y2 = G.multiply(H).mod(p);
                BigInteger T2 = E.multiply(H).mod(p);
                BigInteger Z2 = F.multiply(G).mod(p);
                return new x25519Point(X2, Y2, Z2, T2);
            }

            @Override
            x25519Point x2() {
                BigInteger A = X.modPow(BigInteger.TWO, p);
                BigInteger B = Y.modPow(BigInteger.TWO, p);
                BigInteger C = Z.modPow(BigInteger.TWO, p).multiply(BigInteger.TWO).mod(p);
                BigInteger H = A.add(B).mod(p);
                BigInteger E = sub(H,X.add(Y).modPow(BigInteger.TWO, p));
                BigInteger G = sub(A,B);
                BigInteger F = C.add(G).mod(p);
                BigInteger X2 = E.multiply(F).mod(p);
                BigInteger Y2 = G.multiply(H).mod(p);
                BigInteger T2 = E.multiply(H).mod(p);
                BigInteger Z2 = F.multiply(G).mod(p);
                return new x25519Point(X2, Y2, Z2, T2);
            }
        }
    }

    /**
     * RFC 7748 Ed448 暗号強度 224bit 鍵長 448bit DJB作?
     */
    public static class EdWards448 extends EllipticCurve {
        public EdWards448() {
            super( Ed448, P448, 456, 2, 447, 1, D448, B448, new SHAKE256(114*8),L448); // 448 + 8
        }

        /**
         * 5.2.3. Decoding.
         * @param code 5.2.2で符号化されたもの
         * @return 復元Point
         */
        @Override
        public Point decXY(byte[] code) {
            // 1.
            byte[] by = rev(code);
            int x_0 = by[0] & 0x80;
            by[0] &= 0x7f;
            BigInteger y = new BigInteger(by); //new BigInteger(by);
            if (y.compareTo(p) >= 0) {
                throw new IllegalStateException();
            }
            // 2.
            BigInteger yy = y.modPow(BigInteger.TWO, p); // y.modPow(BigInteger.TWO, curve.p);
            BigInteger u = yy.subtract(BigInteger.ONE).mod(p);
            BigInteger v = d.multiply(yy).subtract(BigInteger.ONE).mod(p);
            BigInteger uv = u.multiply(v).mod(p);
            
            BigInteger x = u.multiply(uv.modPow(p.subtract(THREE).divide(FOUR), p)).mod(p);
            // 3.
            //BigInteger vxx = uv.multiply(v).mod(curve.p);
            BigInteger vxx = v.multiply(x.modPow(BigInteger.TWO, p)).mod(p);
            if ( !vxx.equals(u) ) {
                throw new IllegalStateException();
            }
            // 4.
            if ( x_0 != 0 ) {
                if ( x.equals(BigInteger.ZERO)) {
                    throw new IllegalStateException();
                } else {
                    x = p.subtract(x);
                }
            }
            return new Point(x,y);
        }

        @Override
        x448Point toxPoint(Point x) {
            return new x448Point(x);
        }

        @Override
        xPoint nE(BigInteger x, xPoint p) {
            x448Point r = new x448Point();
            int bl = x.bitLength();
            for (int i = 0; i < bl; i++) {
                if (x.testBit(i)) {
                    r = r.add((x448Point)p);
                }
                p = p.x2();
            }
            return r;
        }
        
        class x448Point extends xPoint {

            x448Point(Point p) {
                X = p.x;
                Y = p.y;
                Z = BigInteger.ONE;
            }

            x448Point() {
                X = BigInteger.ZERO;
                Y = BigInteger.ONE;
                Z = BigInteger.ONE;
            }
            
            x448Point(BigInteger x, BigInteger y, BigInteger z) {
                X = x;
                Y = y;
                Z = z;
            }
            
            @Override
            x448Point add(xPoint b) {
                BigInteger A = Z.multiply(b.Z).mod(p);
                BigInteger B = A.multiply(A).mod(p);
                BigInteger C = X.multiply(b.X).mod(p);
                BigInteger D = Y.multiply(b.Y).mod(p);
                BigInteger E = d.multiply(C).mod(p).multiply(D).mod(p);
                BigInteger F = B.subtract(E).mod(p);
                BigInteger G = B.add(E).mod(p);
                BigInteger H = X.add(Y).mod(p).multiply(b.X.add(b.Y).mod(p)).mod(p);
                BigInteger X1 = A.multiply(F).mod(p).multiply(p.add(p).add(H).subtract(C.add(D)).mod(p));
                BigInteger Y1 = A.multiply(G).mod(p).multiply(p.add(D).subtract(C).mod(p)).mod(p);
                BigInteger Z1 = F.multiply(G).mod(p);
                return new x448Point(X1,Y1,Z1);
            }

            @Override
            x448Point x2() {
                BigInteger B = X.add(Y).modPow(BigInteger.TWO, p);
                BigInteger C = X.modPow(BigInteger.TWO, p);
                BigInteger D = Y.modPow(BigInteger.TWO, p);
                BigInteger E = C.add(D);
                BigInteger H = Z.modPow(BigInteger.TWO, p);
                BigInteger J = E.subtract(H.shiftLeft(1)).mod(p);
                BigInteger X1 = B.subtract(E).multiply(J).mod(p);
                BigInteger Y1 = E.multiply(C.subtract(D)).mod(p);
                BigInteger Z1 = E.multiply(J).mod(p);
                return new x448Point(X1,Y1,Z1);
            }
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
     * Little Endian 変換.
     *
     * @param src 数
     * @param len バイト長
     * @return LE列
     */
    static byte[] itob(BigInteger src, int len) {
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
        BigInteger r = btoi(curve.H.digest()).mod(curve.L);
        byte[] R = curve.nE(r).encXY(curve.b);
        curve.H.update(R);
        curve.H.update(pkey.getA());
        byte[] phM = block.toByteArray(); //curve.PH(); // PH(M)
        BigInteger k = btoi(curve.H.digest(phM)).mod(curve.L);
        BigInteger S = r.add(k.multiply(pkey.gets())).mod(curve.L);
        PacketA d = new PacketA();
        d.write(R);
        d.write(itob(S, curve.b / 8));
        
        preSign();
        return d.toByteArray();
    }

    /**
     * 検証. Verify.
     * @param sign
     * @return
     */
    @Override
    public boolean verify(byte[] sign) {
        EdWards25519 curve = new EdWards25519();
        int hlen = curve.b / 8;
        byte[] Rb = Arrays.copyOfRange(sign, 0, hlen);
        BigInteger S = btoi(Arrays.copyOfRange(sign, hlen, hlen * 2));
        if ( S.compareTo(curve.L) >= 0) {
            throw new IllegalStateException();
        }
        byte[] Ab = pubKey.getA();
        byte[] phM = block.toByteArray();
        curve.H.reset();
        curve.H.update(Rb);
        curve.H.update(Ab);
        byte[] h = curve.H.digest(phM);
        BigInteger k = btoi(h).mod(curve.L);
        Point R = curve.decXY(Rb);
        Point A = curve.decXY(Ab);
        Point RkA = curve.add(R, curve.nE(k, A));
        Point SB = curve.nE(S, curve.B);
        return SB.equals(RkA);
    }
}
