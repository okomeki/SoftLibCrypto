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

/**
 * ECDH X25519のモンゴメリ曲線.
 * 
 */
public class Curve25519 extends Curve {

    public Curve25519() {
        super(P25519, 486662, L25519, 3, 9);
    }

    /**
     * 仮.
     */
    @Override
    BigInteger vCheck(BigInteger v, BigInteger a) {
        BigInteger vv = pow(v, BigInteger.TWO); //v.modPow(BigInteger.TWO, p);
        if (!vv.equals(a)) {
            if (vv.equals(p.subtract(a))) {
                BigInteger z = pow(BigInteger.TWO, p.shiftRight(2).mod(n));
                v = mul(v, z);
            } else {
                throw new IllegalStateException();
            }
        }
        return v;
    }

    @Override
    protected byte[] clearFlag(byte[] bu) {
        byte[] cu = bu.clone();
        cu[cu.length - 1] &= 0x7f;
        return cu;
    }
    
}
