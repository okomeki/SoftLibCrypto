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
 * ECDH Curve448
 */
public class Curve448 extends Curve {

    public Curve448() {
        super(P448, 156326, L448, 2, 5);
        
    }

    /**
     * 仮.
     */
    @Override
    BigInteger vCheck(BigInteger v, BigInteger a) {
        BigInteger vv = v.modPow(BigInteger.TWO, p);
        if (!vv.equals(a)) {
            throw new IllegalStateException(vv.toString() +"!="+ a.toString());
        }
        return v;
    }

    @Override
    protected byte[] clearFlag(byte[] bu) {
        return bu;
    }
    
}
