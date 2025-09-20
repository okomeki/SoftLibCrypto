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
package net.siisise.security.key;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import net.siisise.security.ec.EllipticCurve;

/**
 * FIPS PUB 186-5 ?
 */
public class ECDSAKeyGen {

    public ECDSAPrivateKey genPrivateKey(EllipticCurve.ECCurvep curve) {
        BigInteger x;
        try {
            SecureRandom srnd = SecureRandom.getInstanceStrong();
            BigInteger s = new BigInteger(curve.p.bitLength()*2, srnd); // 1 <= x < n
            x = s.mod(curve.n.subtract(BigInteger.ONE)).add(BigInteger.ONE);
            return new ECDSAPrivateKey(curve, x);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
    
}
