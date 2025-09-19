/*
 * Copyright 2025 okome.
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
package net.siisise.security.ec;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import net.siisise.security.digest.BlockMessageDigest;
import net.siisise.security.digest.SHAKE256;
import net.siisise.security.sign.EdDSA;

/**
 * RFC 7748 Ed448 暗号強度 224bit 鍵長 448bit DJB作?
 * Ed448-Goldilocks
 */
public class EdWards448 extends EdWards {

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

    public EdWards448() {
        super(EdDSA.Ed448, P448, 456, 2, 447, 1, D448G, B448GX, B448GY, L448, SIG448, new byte[0]); // 448 + 8
    } // 448 + 8

    /**
     * ハッシュ
     * @return SHAKE256 114 byte out 
     */
    @Override
    public BlockMessageDigest H() {
        return new SHAKE256(114 * 8l);
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

        private Point448(BigInteger x, BigInteger y, BigInteger z) {
            X = x;
            Y = y;
            Z = z;
        }

        @Override
        public Point448 add(Point b) {
            BigInteger A = mul(Z, b.Z);
            BigInteger B = pow(A, BigInteger.TWO); //.multiply(A).mod(p);
            BigInteger C = mul(X,b.X);
            BigInteger D = mul(Y,b.Y);
            BigInteger E = mul(mul(C, d), D);
            BigInteger F = sub(B, E);
            BigInteger G = addP(B,E);
            BigInteger H = mul(addP(X,Y),addP(b.X,b.Y));
            BigInteger X1 = mul(mul(A, F), sub(H, addP(C, D)));
            BigInteger Y1 = mul(mul(A, G), sub(D,C));
            BigInteger Z1 = mul(F, G);
            return new Point448(X1, Y1, Z1);
        }

        @Override
        Point448 x2() {
            BigInteger B = pow(addP(X, Y),BigInteger.TWO);
            BigInteger C = pow(X, BigInteger.TWO);
            BigInteger D = pow(Y,BigInteger.TWO);
            BigInteger E = addP(C, D);
            BigInteger J = sub(E, pow(Z, BigInteger.TWO).shiftLeft(1));
            BigInteger X1 = mul(sub(B, E), J);
            BigInteger Y1 = mul(E, sub(C, D));
            BigInteger Z1 = mul(E, J);
            return new Point448(X1, Y1, Z1);
        }
    }
    
}
