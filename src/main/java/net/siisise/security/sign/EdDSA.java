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
import java.nio.charset.StandardCharsets;
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

    byte[] dom;
    PacketA block = new PacketA();
    
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
        final xPoint B;
        // 10. 素数
        BigInteger L;
        // 11. prehash
//        MessageDigest PH;

        byte[] SIG;
//        int phflag;
        byte[] ID;
        
        EllipticCurve(OBJECTIDENTIFIER oid, BigInteger p, int b, int c, int n, int a, BigInteger d, BigInteger Bx, BigInteger By, MessageDigest H, BigInteger L, byte[] SIG, byte[] IC) {
            this.oid = oid;
            this.p = p;
            this.b = b;
            this.c = c;
            this.n = n;
            this.a = BigInteger.valueOf(a);
            this.d = d;
            this.B = toxPoint(Bx, By);
            this.H = H;
            this.L = L;
            this.SIG = SIG;
            this.ID = dom(0,IC);
        }
        
        /**
         * ハッシュの頭.
         *
         * @param x
         * @param y dom
         * @return
         */
        final byte[] dom(int x, byte[] y) {
            PacketA dom = new PacketA();
            if ( y != null ) {
                dom.write(SIG);
                dom.write((byte)x);
                dom.write((byte)y.length); // 32bit int
                dom.write(y);
            }
            return dom.toByteArray();
        }

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

        abstract public xPoint decXY(byte[] code);

        BigInteger sub(BigInteger a, BigInteger b) {
            BigInteger s = a.subtract(b);
            if (s.compareTo(BigInteger.ZERO) < 0) {
                return p.add(s);
            }
            return s;
        }

        abstract xPoint toxPoint(BigInteger x, BigInteger y);

        abstract public class xPoint {
            protected BigInteger X;
            protected BigInteger Y;
            protected BigInteger Z;

            void reset() {
                if (!Z.equals(BigInteger.ONE)) {
                    BigInteger r = Z.modInverse(p);
                    Z = BigInteger.ONE;
                    X = X.multiply(r).mod(p);
                    Y = Y.multiply(r).mod(p);
                }
            }
            
            public boolean equals(xPoint p) {
                reset();
                p.reset();
                return X.equals(p.X) && Y.equals(p.Y);
            }
            
            /**
             * 5.1.2. Encoding.
             * @return 
             */
            public byte[] encXY() {
                reset();

                byte[] code = itob(Y, b/8);
                code[code.length - 1] |= X.testBit(0) ? 0x80 : 0;
                return code;
            }
            
            abstract xPoint add(xPoint x);
            abstract xPoint x2();

            xPoint nE(BigInteger x) {
                xPoint r = toxPoint(BigInteger.ZERO,BigInteger.ONE);
                xPoint p = this;
                int bl = x.bitLength();
                for (int i = 0; i < bl; i++) {
                    if (x.testBit(i)) {
                        r = r.add(p);
                    }
                    p = p.x2();
                }
                return r;
            }
        }

        public byte[] nE(BigInteger x) {
            return B.nE(x).encXY();
        }
    }

    static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger D25519 = new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555");
    static final BigInteger B25519X = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
    static final BigInteger B25519Y = new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960");
    static final BigInteger L25519 = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    static final byte[] SIG25519 = "SigEd25519 no Ed25519 collisions".getBytes(StandardCharsets.ISO_8859_1);

    // RFC 8032 5.2. Ed448
    // Ed448-Goldilocks 側の値を使用する
    static final BigInteger P448 = BigInteger.ONE.shiftLeft(448).subtract(BigInteger.ONE.shiftLeft(224).add(BigInteger.ONE));
//    static final BigInteger D448 = new BigInteger("611975850744529176160423220965553317543219696871016626328968936415087860042636474891785599283666020414768678979989378147065462815545017");
//    static final Point B448 = new Point(new BigInteger("345397493039729516374008604150537410266655260075183290216406970281645695073672344430481787759340633221708391583424041788924124567700732"),
//            new BigInteger("363419362147803445274661903944002267176820680343659030140745099590306164083365386343198191849338272965044442230921818680526749009182718"));
    static final BigInteger L448 = BigInteger.ONE.shiftLeft(446).subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));

    static final BigInteger D448G = P448.add(BigInteger.valueOf(-39081));
//    static final BigInteger D448G = P448.subtract(BigInteger.valueOf(-39081));
    static final BigInteger B448GX = new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710");
    static final BigInteger B448GY = new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660");
//    static final byte[] SIGED25519 = "SigEd25519 no Ed25519 collisions".getBytes(StandardCharsets.ISO_8859_1);
    static final byte[] SIG448 = "SigEd448".getBytes(StandardCharsets.ISO_8859_1);

    /**
     * RFC 7748 Ed25519 暗号強度 128bit 鍵長 256bit DJB作?
     */
    public static class EdWards25519 extends EllipticCurve {
        public EdWards25519() {
            super(Ed25519, P25519, 256, 3, 254, -1, D25519, B25519X, B25519Y, new SHA512(),L25519, SIG25519, null);
        }

        /**
         * 5.1.3. Decoding.
         * @param code 5.1.2で符号化されたもの
         * @return 復元Point
         */
        @Override
        public xPoint decXY(byte[] code) {
            // 1.
            byte[] by = rev(code);
            boolean x_0 = (by[0] & 0x80) != 0;
            by[0] &= 0x7f;
            BigInteger y = new BigInteger(by); //new BigInteger(by);
            if (y.compareTo(p) >= 0) {
                throw new IllegalStateException();
            }
            // 2.
            BigInteger yy = y.modPow(BigInteger.TWO, p);
            BigInteger u = sub(yy,BigInteger.ONE);
            BigInteger v = d.multiply(yy).add(BigInteger.ONE).mod(p);
            BigInteger uv = u.multiply(v).mod(p);
            BigInteger x = u.multiply(uv.modPow(p.shiftRight(3), p)).mod(p);
            // 3.
            BigInteger vxx = v.multiply(x.modPow(BigInteger.TWO, p)).mod(p);
            if ( !vxx.equals(u) ) {
                if (vxx.equals(p.subtract(u))) {
                    BigInteger z = BigInteger.TWO.modPow(p.shiftRight(2), p);
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
            return new x25519Point(x,y);
        }
        
        @Override
        x25519Point toxPoint(BigInteger x, BigInteger y) {
            return new x25519Point(x,y);
        }

        class x25519Point extends xPoint {

            BigInteger T;

            x25519Point(BigInteger x, BigInteger y) {
                Z = BigInteger.ONE;
                X = x;
                Y = y;
                T = x.multiply(y).mod(p);
            }

            x25519Point(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) {
                this.X = X;
                this.Y = Y;
                this.Z = Z;
                this.T = T;
            }
            
            @Override
            void reset() {
                super.reset();
                T = X.multiply(Y);
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
     * Ed448-Goldilocks
     */
    public static class EdWards448 extends EllipticCurve {
        public EdWards448() {
            super( Ed448, P448, 456, 2, 447, 1, D448G, B448GX, B448GY, new SHAKE256(114*8l), L448, SIG448, new byte[0]); // 448 + 8
        }
        
        /**
         * 5.2.3. Decoding.
         * @param code 5.2.2で符号化されたもの
         * @return 復元Point
         */
        @Override
        public xPoint decXY(byte[] code) {
            // 1.
            byte[] by = rev(code);
            boolean x_0 = (by[0] & 0x80) != 0;
            by[0] &= 0x7f;
            BigInteger y = new BigInteger(by);
            if (y.compareTo(p) >= 0) {
                throw new IllegalStateException();
            }
            // 2.
            BigInteger yy = y.modPow(BigInteger.TWO, p); // y.modPow(BigInteger.TWO, getCurve.p);
            BigInteger u = yy.subtract(BigInteger.ONE).mod(p);
            BigInteger v = d.multiply(yy).subtract(BigInteger.ONE).mod(p);
            BigInteger uv = u.multiply(v).mod(p);
            
            BigInteger x = u.multiply(uv.modPow(p.shiftRight(2), p)).mod(p);
            // 3.
            BigInteger vxx = v.multiply(x.modPow(BigInteger.TWO, p)).mod(p);
            if ( !vxx.equals(u) ) {
                throw new IllegalStateException();
            }
            // 4.
            if ( x_0 && x.equals(BigInteger.ZERO)) {
                throw new IllegalStateException();
            }
            if (x.testBit(0) != x_0) {
                x = p.subtract(x);
            }
            return new x448Point(x,y);
        }

        @Override
        x448Point toxPoint(BigInteger x, BigInteger y) {
            return new x448Point(x, y);
        }

        class x448Point extends xPoint {

            x448Point(BigInteger x, BigInteger y) {
                Z = BigInteger.ONE;
                X = x;
                Y = y;
            }

            x448Point(BigInteger x, BigInteger y, BigInteger z) {
                X = x;
                Y = y;
                Z = z;
            }

            @Override
            x448Point add(xPoint b) {
                BigInteger A = Z.multiply(b.Z).mod(p);
                BigInteger B = A.modPow(BigInteger.TWO, p); //.multiply(A).mod(p);
                BigInteger C = X.multiply(b.X).mod(p);
                BigInteger D = Y.multiply(b.Y).mod(p);
                BigInteger E = d.multiply(C).mod(p).multiply(D).mod(p);
                BigInteger F = sub(B, E);
                BigInteger G = B.add(E).mod(p);
                BigInteger H = X.add(Y).mod(p).multiply(b.X.add(b.Y).mod(p)).mod(p);
                BigInteger X1 = A.multiply(F).mod(p).multiply(sub(sub(H,C),D)).mod(p);
                BigInteger Y1 = A.multiply(G).mod(p).multiply(sub(D,C)).mod(p);
                BigInteger Z1 = F.multiply(G).mod(p);
                return new x448Point(X1,Y1,Z1);
            }

            @Override
            x448Point x2() {
                BigInteger B = X.add(Y).modPow(BigInteger.TWO, p);
                BigInteger C = X.modPow(BigInteger.TWO, p);
                BigInteger D = Y.modPow(BigInteger.TWO, p);
                BigInteger E = C.add(D).mod(p);
                BigInteger H = Z.modPow(BigInteger.TWO, p);
                BigInteger J = sub(E,(BigInteger.TWO.multiply(H).mod(p)));
                BigInteger X1 = sub(B,E).multiply(J).mod(p);
                BigInteger Y1 = E.multiply(sub(C,D)).mod(p);
                BigInteger Z1 = E.multiply(J).mod(p);
                return new x448Point(X1,Y1,Z1);
            }
        }
    }

    public static EdWards25519 init25519() {
        return new EdWards25519();
    }

    public static EdWards448 init448() {
        return new EdWards448();
    }

    public EdDSA() {
    }

    public EdDSA(EdDSAPrivateKey k) {
        pkey = k;
        dom = k.getCurve().ID;
        preSign();
    }

    public EdDSA(EdDSAPublicKey pub) {
        pubKey = pub;
        dom = pub.getCurve().ID;
    }

    void preSign() {
        byte[] hkey = pkey.init();
        EdDSA.EllipticCurve curve = pkey.getCurve();
        int hlen = curve.b / 8;
        MessageDigest h = curve.H;
        h.reset();
        h.update(dom);
        h.update(hkey, hlen, hlen);
    }

    /**
     * 秘密鍵長?
     *
     * @return 秘密鍵長(バイト)
     */
    @Override
    public int getKeyLength() {
        return pkey.getCurve().b / 8;
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        if ( pkey != null) {
            pkey.getCurve().H.update(src, offset, length);
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
        int offset = src.length + ((src[src.length - 1] < 0) ? 1 : 0);
        byte[] code = new byte[offset];
        
        for (int i = 0; i < src.length; i++) {
            code[--offset] = src[i];
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
        byte[] key = new byte[curve.b / 8]; // ?
        SecureRandom srnd;
        try {
            srnd = SecureRandom.getInstanceStrong();
            srnd.nextBytes(key);
            pkey = new EdDSAPrivateKey(curve,key);
            dom = curve.ID;
            preSign();
            OCTETSTRING oct = new OCTETSTRING(key);
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
     * RFC 8032 5.2.6. Sign
     * 2.のPH(M)の後、r生成から
     */
    @Override
    public byte[] sign() {
        EllipticCurve curve = pkey.getCurve();
        // 2.
        BigInteger r = btoi(curve.H.digest()).mod(curve.L);
        // 3.
        byte[] R = curve.B.nE(r).encXY();
        curve.H.update(dom);
        curve.H.update(R);
        curve.H.update(pkey.getA());
        byte[] phM = block.toByteArray(); //curve.PH(); // PH(M)
        curve.H.update(phM);
        BigInteger k = btoi(curve.H.digest()).mod(curve.L);

        BigInteger s = pkey.gets();
        BigInteger SI = r.add(k.multiply(s).mod(curve.L)).mod(curve.L);
        byte[] S = itob(SI, curve.b / 8);
        PacketA d = new PacketA();
        d.write(R);
        d.write(S);
        
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
        EllipticCurve curve = pubKey.getCurve();
        int hlen = curve.b / 8;
        byte[] Rb = Arrays.copyOfRange(sign, 0, hlen);
        BigInteger S = btoi(Arrays.copyOfRange(sign, hlen, hlen * 2));
        if ( S.compareTo(curve.L) >= 0) {
            throw new IllegalStateException();
        }
        byte[] Ab = pubKey.getA();
        byte[] phM = block.toByteArray();
        curve.H.reset();
        curve.H.update(dom);
        curve.H.update(Rb);
        curve.H.update(Ab);
        byte[] h = curve.H.digest(phM);
        BigInteger k = btoi(h).mod(curve.L);
        EllipticCurve.xPoint R = curve.decXY(Rb);
        EllipticCurve.xPoint A = curve.decXY(Ab);
        EllipticCurve.xPoint RkA = R.add(A.nE(k));
        EllipticCurve.xPoint SB = curve.B.nE(S);
        return SB.equals(RkA);
    }
}
