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
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;

/**
 * Fp な曲線.
 * generator
 */
class Curvep<P extends Curvep.Pointp> extends EllipticCurve {

    public class Pointp extends Point {

        Pointp(BigInteger x, BigInteger y) {
            super(x, y);
        }

        public Pointp x(BigInteger n) {
            throw new IllegalStateException();
        }
    }
    /**
     * 始点
     */
    public final P G;

    /**
     * 既存の楕円曲線.
     * @param oid OBJECTIDENTIFIER
     * @param p
     * @param Gx generator 始点 x
     * @param Gy generator 始点 y
     * @param order
     * @param h
     */
    Curvep(OBJECTIDENTIFIER oid, BigInteger p, BigInteger Gx, BigInteger Gy, BigInteger order, int h) {
        super(oid, p, order, h);
        G = toPoint(Gx, Gy);
    }

    Curvep(BigInteger p, BigInteger Gx, BigInteger Gy, BigInteger order, int h) {
        super(p, order, h);
        G = toPoint(Gx, Gy);
    }

    public P getG() {
        return G;
    }

    @Override
    public P toPoint(BigInteger x, BigInteger y) {
        return (P) new Pointp(x, y);
    }

    protected final BigInteger add(BigInteger a, BigInteger b) {
        return a.add(b).mod(p);
    }

    /*
    protected final BigInteger mod(BigInteger a, BigInteger b) {
    return a.mod(b);
    }
     */
    protected final BigInteger sub(BigInteger a, BigInteger b) {
        return a.add(p).subtract(b).mod(p);
    }

    protected final BigInteger mul(BigInteger a, BigInteger b) {
        return a.multiply(b).mod(p);
    }

    protected final BigInteger pow(BigInteger a, BigInteger b) {
        return a.modPow(b, p);
    }

    protected final BigInteger pow(BigInteger a, long b) {
        return pow(a, BigInteger.valueOf(b));
    }

    protected final BigInteger div(BigInteger a, BigInteger b) {
        return a.multiply(b.modInverse(p)).mod(p);
    }

    public boolean equals(Object o) {
        if (o instanceof Curvep) {
            Curvep og = (Curvep) o;
            if (G.getX().equals(og.G.getX()) && G.getY().equals(og.G.getY())) {
                super.equals(o);
            }
        }
        return false;
    }
    
}
