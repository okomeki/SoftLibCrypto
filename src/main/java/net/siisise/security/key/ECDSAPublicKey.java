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
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import net.siisise.security.ec.EllipticCurve;

/**
 * まだ限定 ECCurvep
 */
public class ECDSAPublicKey implements ECPublicKey {

    EllipticCurve.ECCurvep curve;
    ECParameterSpec spec;

    public ECDSAPublicKey(ECParameterSpec spec) {
        this.spec = spec;
    }
    
    public ECDSAPublicKey(EllipticCurve.ECCurvep curve, BigInteger x) {
        this.curve = curve;
    }
    
    

    @Override
    public ECPoint getW() {
//        return new ECPoint();
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public EllipticCurve.ECCurvep getCurve() {
        return curve;
    }

    /**
     * ECDSAなのかECなのか.
     *
     * @return ?
     */
    @Override
    public String getAlgorithm() {
        return "EC";
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public ECParameterSpec getParams() {
        return spec;
    }

}
