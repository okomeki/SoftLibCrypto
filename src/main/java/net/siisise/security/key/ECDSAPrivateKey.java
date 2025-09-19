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
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.security.ec.EllipticCurve;
import net.siisise.security.sign.ECDSA;

/**
 * ECDSA 秘密鍵.
 * 曲線とパラメータx
 */
public class ECDSAPrivateKey implements ECPrivateKey {

    final EllipticCurve.ECCurvep curve;
    ECParameterSpec spec;
    final BigInteger x;

    public ECDSAPrivateKey(EllipticCurve.ECCurvep c, BigInteger x) {
        curve = c;
        this.x = x;//.mod(c.n);
    }
    
    public ECDSAPrivateKey(ECParameterSpec spec, BigInteger x) {
        this.spec = spec;
        curve = ECDSA.toCurve(spec);
        this.x = x;
    }

    @Override
    public String getAlgorithm() {
        return "ECDSA";
    }

    @Override
    public String getFormat() {
        return "PKCS#8";
    }

    /**
     * x のみ.
     *
     * @return x
     */
    @Override
    public byte[] getEncoded() {
        return PKCS1.I2OSP(x, 0);
    }

    public EllipticCurve.ECCurvep getCurve() {
        return curve;
    }

    @Override
    public BigInteger getS() {
        return x;
    }

    @Override
    public ECParameterSpec getParams() {
        return spec;
    }
}
