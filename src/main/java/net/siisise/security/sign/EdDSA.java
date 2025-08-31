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
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import net.siisise.io.Output;
import net.siisise.io.PacketA;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.lang.Bin;
import net.siisise.security.digest.BlockMessageDigest;
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
public class EdDSA extends Output.AbstractOutput implements SignVerify {

    public static final OBJECTIDENTIFIER X25519 = new OBJECTIDENTIFIER("1.3.101.110");
    public static final OBJECTIDENTIFIER X448 = new OBJECTIDENTIFIER("1.3.101.111");
    public static final OBJECTIDENTIFIER Ed25519 = new OBJECTIDENTIFIER("1.3.101.112");
    public static final OBJECTIDENTIFIER Ed448 = new OBJECTIDENTIFIER("1.3.101.113");

    /**
     * パラメータ. ECDSAと同じ? RFC 8032 3.のパラメータ
     */
    public abstract static class EdWards {

        public final OBJECTIDENTIFIER oid;

        // 1. GF(p) 奇数
        final BigInteger p;
        // 2. 鍵と署名のサイズの元 2^(b-1) > p
        public final int b;
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
        final Point ZP;
        // 10. 素数
        public final BigInteger L;
        // 11. prehash
//        MessageDigest PH;

        private final byte[] SIG;
        /**
         * 空dom
         */
        byte[] ID;

        EdWards(OBJECTIDENTIFIER oid, BigInteger p, int b, int c, int n, int a, BigInteger d, BigInteger Bx, BigInteger By, BigInteger L, byte[] SIG, byte[] IC) {
            this.oid = oid;
            this.p = p;
            this.b = b;
            this.c = c;
            this.n = n;
            this.a = BigInteger.valueOf(a);
            this.d = d;
//            this.B = decXY(itob(By,b));
            this.B = toPoint(Bx, By);
            this.ZP = toPoint(BigInteger.ZERO, BigInteger.ONE);
            this.L = L;
            this.SIG = SIG;
            this.ID = dom(0, IC);
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
            if (y != null) {
                dom.write(SIG);
                dom.write((byte) x);
                dom.write((byte) y.length); // 32bit int
                dom.write(y);
            }
            return dom.toByteArray();
        }
        
        abstract public BlockMessageDigest H();

        /*
         * PH ぷりハッシュ計算.
         *
         * @param x message
         * @return hash
         */
        public byte[] PH(byte[] x) {
            return x;
        }

        /**
         * Little Endian 変換.
         *
         * @param src 数
         * @return LE列
         */
        public byte[] itob(BigInteger src) {
            byte[] code = src.toByteArray();
            byte[] dst = new byte[b/8];
            if (code[0] < 0 && dst.length > code.length) {
                Arrays.fill(dst, code.length, dst.length, (byte) 0xff);
            }
            int offset = 0;
            for (int i = code.length - 1; i >= 0; i--) {
                dst[offset++] = code[i];
            }
            return dst;
        }

        public BigInteger cuts(byte[] s) {
            s[0] &= 0xff << c;
            s = Bin.rev(s);
            int n = s.length - this.n / 8 - 1;
            for (int i = 0; i < n; i++) {
                s[i] = 0;
            }
            s[n] &= 0xff >>> (7 - (this.n % 8));
            s[n] |= 1 << (this.n % 8);
            return new BigInteger(s);
        }

        /**
         * s mod L  の符号化.
         * 
         * @param s
         * @return s mod L の符号化
         */
        public byte[] ENC(BigInteger s) {
            return itob(s.mod(L));
        }

        abstract public class Point {

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

            public boolean equals(Point p) {
//                reset();
//                p.reset();
                return X.multiply(p.Z).subtract(p.X.multiply(Z)).mod(EdWards.this.p).equals(BigInteger.ZERO)
                    && Y.multiply(p.Z).subtract(p.Y.multiply(Z)).mod(EdWards.this.p).equals(BigInteger.ZERO);
            }

            /**
             * 5.1.2. Encoding.
             *
             * @return
             */
            public byte[] encXY() {
                reset();

                byte[] code = itob(Y);
                code[code.length - 1] |= X.testBit(0) ? 0x80 : 0;
                return code;
            }

            abstract Point add(Point x);

            abstract Point x2();

            Point nE(BigInteger x) {
                Point r = ZP;
                Point p = this;
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

        /**
         * 5.1.3. Decoding.
         * 5.2.3.
         *
         * @param code 5.1.2で符号化されたもの
         * @return 復元Point
         */
        public Point decXY(byte[] code) {
            // 1. xフラグとy座標の分離
            byte[] by = Bin.rev(code);
            boolean x_0 = (by[0] & 0x80) != 0;
            by[0] &= 0x7f;
            BigInteger y = new BigInteger(by);
            if (y.compareTo(p) >= 0) {
                throw new IllegalStateException();
            }
            // 2. 
            // EdWards25519 x^2 = (y^2 - 1)(dy^2 + 1)
            // EdWards448   x^2 = (y^2 - 1)(dy^2 - 1)
            BigInteger yy = y.modPow(BigInteger.TWO, p);
            BigInteger u = yy.subtract(BigInteger.ONE);
            BigInteger v = d.multiply(yy).subtract(a).mod(p);
            BigInteger uv = u.multiply(v).mod(p);
            BigInteger x = u.multiply(uv.modPow(p.shiftRight(c), p)).mod(p);
            // 3.
            BigInteger vxx = v.multiply(x.modPow(BigInteger.TWO, p)).mod(p);
            x = xCheck(x, vxx, u);
            // 4.
            if (x_0 && x.equals(BigInteger.ZERO)) {
                throw new IllegalStateException();
            }
            if (x.testBit(0) != x_0) {
                x = p.subtract(x);
            }
            return toPoint(x, y);
        }
        
        abstract BigInteger xCheck(BigInteger x, BigInteger vxx, BigInteger u);


        abstract Point toPoint(BigInteger x, BigInteger y);

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

    static final BigInteger D448G = BigInteger.valueOf(-39081);
    static final BigInteger B448GX = new BigInteger("224580040295924300187604334099896036246789641632564134246125461686950415467406032909029192869357953282578032075146446173674602635247710");
    static final BigInteger B448GY = new BigInteger("298819210078481492676017930443930673437544040154080242095928241372331506189835876003536878655418784733982303233503462500531545062832660");
//    static final byte[] SIGED25519 = "SigEd25519 no Ed25519 collisions".getBytes(StandardCharsets.ISO_8859_1);
    static final byte[] SIG448 = "SigEd448".getBytes(StandardCharsets.ISO_8859_1);

    /**
     * RFC 7748 Ed25519 暗号強度 128bit 鍵長 256bit DJB作?
     */
    public static class EdWards25519 extends EdWards {

        public EdWards25519() {
            super(Ed25519, P25519, 256, 3, 254, -1, D25519, B25519X, B25519Y, L25519, SIG25519, null);
        }
        
        @Override
        public BlockMessageDigest H() {
            return new SHA512();
        }

        @Override
        BigInteger xCheck(BigInteger x, BigInteger vxx, BigInteger u) {
            if (!vxx.equals(u)) {
                if (vxx.equals(p.subtract(u))) {
                    BigInteger z = BigInteger.TWO.modPow(p.shiftRight(2), p);
                    x = x.multiply(z).mod(p);
                } else {
                    throw new IllegalStateException();
                }
            }
            return x;
        }

        @Override
        Point25519 toPoint(BigInteger x, BigInteger y) {
            return new Point25519(x, y);
        }

        class Point25519 extends Point {

            // x * y
            BigInteger T;

            Point25519(BigInteger x, BigInteger y) {
                Z = BigInteger.ONE;
                X = x;
                Y = y;
                T = x.multiply(y).mod(p);
            }

            Point25519(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) {
                this.X = X;
                this.Y = Y;
                this.Z = Z;
                this.T = T;
            }

            @Override
            void reset() {
                super.reset();
                T = X.multiply(Y).mod(p);
            }

            @Override
            Point25519 add(Point sb) {
                Point25519 b = (Point25519) sb;
                BigInteger A = Y.subtract(X).multiply(b.Y.subtract(b.X)).mod(p);
                BigInteger B = Y.add(X).multiply(b.Y.add(b.X)).mod(p);
                BigInteger C = T.multiply(d).shiftLeft(1).mod(p).multiply(b.T).mod(p);
                BigInteger D = Z.multiply(b.Z).shiftLeft(1).mod(p);
                BigInteger H = B.add(A);
                BigInteger E = B.subtract(A);
                BigInteger G = D.add(C);
                BigInteger F = D.subtract(C);

                BigInteger X2 = E.multiply(F).mod(p);
                BigInteger Y2 = G.multiply(H).mod(p);
                BigInteger T2 = E.multiply(H).mod(p);
                BigInteger Z2 = F.multiply(G).mod(p);
                return new Point25519(X2, Y2, Z2, T2);
            }

            @Override
            Point25519 x2() {
                BigInteger A = X.modPow(BigInteger.TWO, p);
                BigInteger B = Y.modPow(BigInteger.TWO, p);
                BigInteger C = Z.modPow(BigInteger.TWO, p).shiftLeft(1);
                BigInteger H = A.add(B);
                BigInteger E = H.subtract(X.add(Y).modPow(BigInteger.TWO, p)); // B
                BigInteger G = A.subtract(B);
                BigInteger F = C.add(G);

                BigInteger X2 = E.multiply(F).mod(p);
                BigInteger Y2 = G.multiply(H).mod(p);
                BigInteger T2 = E.multiply(H).mod(p);
                BigInteger Z2 = F.multiply(G).mod(p);
                return new Point25519(X2, Y2, Z2, T2);
            }
        }
    }

    /**
     * RFC 7748 Ed448 暗号強度 224bit 鍵長 448bit DJB作?
     * Ed448-Goldilocks
     */
    public static class EdWards448 extends EdWards {

        public EdWards448() {
            super(Ed448, P448, 456, 2, 447, 1, D448G, B448GX, B448GY, L448, SIG448, new byte[0] ); // 448 + 8
        }

        @Override
        public BlockMessageDigest H() {
            return new SHAKE256(114*8l);
        }

        @Override
        BigInteger xCheck(BigInteger x, BigInteger vxx, BigInteger u) {
            if (!vxx.equals(u)) {
                throw new IllegalStateException();
            }
            return x;
        }

        @Override
        Point448 toPoint(BigInteger x, BigInteger y) {
            return new Point448(x, y);
        }

        class Point448 extends Point {

            Point448(BigInteger x, BigInteger y) {
                Z = BigInteger.ONE;
                X = x;
                Y = y;
            }

            Point448(BigInteger x, BigInteger y, BigInteger z) {
                X = x;
                Y = y;
                Z = z;
            }

            @Override
            Point448 add(Point b) {
                BigInteger A = Z.multiply(b.Z).mod(p);
                BigInteger B = A.modPow(BigInteger.TWO, p); //.multiply(A).mod(p);
                BigInteger C = X.multiply(b.X).mod(p);
                BigInteger D = Y.multiply(b.Y).mod(p);
                BigInteger E = d.multiply(C).mod(p).multiply(D).mod(p);
                BigInteger F = B.subtract(E);
                BigInteger G = B.add(E);
                BigInteger H = X.add(Y).multiply(b.X.add(b.Y)).mod(p);
                BigInteger X1 = A.multiply(F).mod(p).multiply(H.subtract(C.add(D))).mod(p);
                BigInteger Y1 = A.multiply(G).mod(p).multiply(D.subtract(C)).mod(p);
                BigInteger Z1 = F.multiply(G).mod(p);
                return new Point448(X1, Y1, Z1);
            }

            @Override
            Point448 x2() {
                BigInteger B = X.add(Y).modPow(BigInteger.TWO, p);
                BigInteger C = X.modPow(BigInteger.TWO, p);
                BigInteger D = Y.modPow(BigInteger.TWO, p);
                BigInteger E = C.add(D);
                BigInteger J = E.subtract((Z.modPow(BigInteger.TWO, p).shiftLeft(1)));
                BigInteger X1 = B.subtract(E).multiply(J).mod(p);
                BigInteger Y1 = E.multiply(C.subtract(D)).mod(p);
                BigInteger Z1 = E.multiply(J).mod(p);
                return new Point448(X1, Y1, Z1);
            }
        }
    }

    public static EdWards25519 init25519() {
        return new EdWards25519();
    }

    public static EdWards448 init448() {
        return new EdWards448();
    }

    /**
     * Ed25519 32byte 256bit
     * Ed448
     */
    EdDSAPrivateKey pkey;
    EdDSAPublicKey pubKey;
    BlockMessageDigest H;

    byte[] dom;
    PacketA block = new PacketA();

    public EdDSA() {
    }

    public EdDSA(EdDSAPrivateKey k) {
        pkey = k;
        dom = k.getCurve().ID;
        preSign();
    }

    public EdDSA(EdDSAPrivateKey k, byte[] context) {
        pkey = k;
        EdDSA.EdWards curve = k.getCurve();
        if (context != null && context.length > 0) {
            dom = curve.dom(0, context);
        } else {
            dom = k.getCurve().ID;
        }
        preSign();
    }

    public EdDSA(EdDSAPublicKey pub) {
        pubKey = pub;
        dom = pub.getCurve().ID;
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
        if (pkey != null) {
            H.update(src, offset, length);
        }
        block.write(src, offset, length);
    }

    /**
     * 秘密鍵.
     * RFC 8410 CurvePrivateKey の形式
     * PKCS #8 の privateKey OCTETSTRING
     *
     * @param curve 曲線
     * @return OCTETSTRING な形式?
     */
    public byte[] genPrvKey(EdWards curve) {
        byte[] key = new byte[curve.b / 8]; // ?
        SecureRandom srnd;
        try {
            srnd = SecureRandom.getInstanceStrong();
            srnd.nextBytes(key);
            pkey = new EdDSAPrivateKey(curve, key);
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
        if (pubKey == null) {
            pubKey = pkey.getPublicKey();
        }
        return pubKey.getA();
    }

    void preSign() {
        byte[] prefix = pkey.getPrefix();
        EdDSA.EdWards curve = pkey.getCurve();
        H = curve.H();
        H.update(dom);
        H.update(prefix);
    }

    /**
     * RFC 8032 5.1.6. Sign
     * RFC 8032 5.2.6. Sign
     * 2.のPH(M)の後、r生成から
     */
    @Override
    public byte[] sign() {
        EdWards curve = pkey.getCurve();
        // 2.
        BigInteger r = Bin.lbtobi(H.digest()).mod(curve.L);
        // 3.
        byte[] R = curve.nE(r); // チェック済み
        H.update(dom);
        H.update(R);
        H.update(pkey.getA());
        byte[] phM = block.toByteArray(); //curve.PH(); // PH(M)
        H.update(phM);

        BigInteger k = Bin.lbtobi(H.digest()).mod(curve.L);
        BigInteger s = pkey.gets();
        byte[] S = curve.ENC(r.add(k.multiply(s)));
        PacketA d = new PacketA();
        d.dwrite(R);
        d.dwrite(S);

        preSign();
        return d.toByteArray();
    }

    /**
     * 検証. Verify.
     *
     * @param sign
     * @return
     */
    @Override
    public boolean verify(byte[] sign) {
        byte[] Ab = genPubKey();
        EdWards curve = pubKey.getCurve();
        int hlen = curve.b / 8;
        byte[] Rb = Arrays.copyOfRange(sign, 0, hlen);
        BigInteger S = Bin.lbtobi(Arrays.copyOfRange(sign, hlen, hlen * 2));
        System.out.println("S:" + S);
        if (S.compareTo(curve.L) >= 0) {
            throw new IllegalStateException();
        }
        byte[] phM = block.toByteArray();
        H = curve.H();
        H.update(dom);
        H.update(Rb);
        H.update(Ab);
        byte[] h = H.digest(phM);
        BigInteger k = Bin.lbtobi(h).mod(curve.L);
        EdWards.Point R = curve.decXY(Rb);
        EdWards.Point A = curve.decXY(Ab);
        EdWards.Point RkA = R.add(A.nE(k));
        EdWards.Point SB = curve.B.nE(S);
        return SB.equals(RkA);
    }
}
