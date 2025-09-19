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
import net.siisise.security.digest.SHA512;
import net.siisise.security.sign.EdDSA;

/**
 * RFC 7748 Ed25519.
 * 暗号強度 128bit 鍵長 256bit DJB作?
 */
public class EdWards25519 extends EdWards {

    static final BigInteger P25519 = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    static final BigInteger D25519 = new BigInteger("37095705934669439343138083508754565189542113879843219016388785533085940283555");
    static final BigInteger B25519X = new BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202");
    static final BigInteger B25519Y = new BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960");
    static final BigInteger L25519 = BigInteger.ONE.shiftLeft(252).add(new BigInteger("27742317777372353535851937790883648493"));
    static final byte[] SIG25519 = "SigEd25519 no Ed25519 collisions".getBytes(StandardCharsets.ISO_8859_1);

    public EdWards25519() {
        super(EdDSA.Ed25519, P25519, 256, 3, 254, -1, D25519, B25519X, B25519Y, L25519, SIG25519, null);
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
                x = mul(x,z);
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
            T = mul(X, Y);
        }

        private Point25519(BigInteger X, BigInteger Y, BigInteger Z, BigInteger T) {
            this.X = X;
            this.Y = Y;
            this.Z = Z;
            this.T = T;
        }

        @Override
        void reset() {
            super.reset();
            T = mul(X, Y);
        }

        @Override
        public Point25519 add(Point sb) {
            Point25519 b = (Point25519) sb;
            BigInteger A = mul(sub(Y,X),sub(b.Y, b.X));
            BigInteger B = mul(addP(Y, X), addP(b.Y, b.X));
            BigInteger C = mul(b.T, mul(T, d).shiftLeft(1));
            BigInteger D = Z.multiply(b.Z).shiftLeft(1).mod(p);
            BigInteger H = addP(A, B);
            BigInteger E = sub(B, A);
            BigInteger G = addP(D, C);
            BigInteger F = sub(D, C);
            BigInteger X2 = mul(E, F);
            BigInteger Y2 = mul(H, G);
            BigInteger T2 = mul(E, H);
            BigInteger Z2 = mul(F, G);
            return new Point25519(X2, Y2, Z2, T2);
        }

        @Override
        Point25519 x2() {
            BigInteger A = pow(X, BigInteger.TWO);
            BigInteger B = pow(Y, BigInteger.TWO);
            BigInteger C = Z.modPow(BigInteger.TWO, p).shiftLeft(1);
            BigInteger H = addP(A, B);
            BigInteger E = sub(H, pow(addP(X,Y),BigInteger.TWO)); // B
            BigInteger G = sub(A, B);
            BigInteger F = addP(G,C);
            BigInteger X2 = mul(E, F);
            BigInteger Y2 = mul(H, G);
            BigInteger T2 = mul(E, H);
            BigInteger Z2 = mul(F, G);
            return new Point25519(X2, Y2, Z2, T2);
        }
    }
    
}
