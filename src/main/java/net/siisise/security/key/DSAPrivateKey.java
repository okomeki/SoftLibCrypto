/*
 * Copyright 2023 okome.
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
import java.security.interfaces.DSAParams;

/**
 *
 */
public class DSAPrivateKey implements java.security.interfaces.DSAPrivateKey {
    private final BigInteger x;
    private final DSAParams params;

    public DSAPrivateKey(BigInteger x, BigInteger p, BigInteger q, BigInteger g) {
        this.x = x;
        params = new DSADomain(p,q,g);
    }
    
    public DSAPrivateKey(BigInteger x, DSAParams params) {
        this.x = x;
        this.params = params;
    }
    
    @Override
    public BigInteger getX() {
        return x;
    }

    /**
     * DSA秘密鍵/公開鍵共通部分
     * @return 
     */
    @Override
    public DSAParams getParams() {
        return params;
    }

    @Override
    public String getAlgorithm() {
        return "DSA";
    }

    /**
     * X.509 または PKCS#8 など
     * @return 
     */
    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] getEncoded() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
    public DSAPublicKey getPublicKey() {
        BigInteger y = params.getG().modPow(x, params.getP());
        return new DSAPublicKey(y, params);
    }
    
}
