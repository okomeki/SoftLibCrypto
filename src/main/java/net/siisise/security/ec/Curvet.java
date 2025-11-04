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
 * 仮 F2^m
 */
public class Curvet<P extends Curvet.Pointt> extends EllipticCurve {

    public class Pointt extends Point {

        public Pointt(BigInteger x, BigInteger y) {
            super(x, y);
        }

        @Override
        public Pointt x(BigInteger k) {
            throw new IllegalStateException();
        }
    }

    Curvet(OBJECTIDENTIFIER oid, BigInteger p, BigInteger order, int h) {
        super(oid, p, order, h);
    }
    
}
