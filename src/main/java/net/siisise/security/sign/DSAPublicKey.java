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
package net.siisise.security.sign;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

/**
 * DSA公開鍵.
 * 秘密鍵と共通の値 p q g
 * 固有の値 y
 */
public class DSAPublicKey implements java.security.interfaces.DSAPublicKey {
    private final BigInteger y;
    private final DSAParams params;

    /**
     * 
     * @param y DSA公開鍵成分
     * @param params DSA秘密鍵公開鍵共通成分 p q g
     */
    public DSAPublicKey(BigInteger y, DSAParams params ) {
        this.y = y;
        this.params = params;
    }

    /**
     * DSA公開鍵
     * @param y DSA公開鍵成分
     * @param p 
     * @param q
     * @param g 
     */
    public DSAPublicKey(BigInteger y, BigInteger p, BigInteger q, BigInteger g ) {
        this.y = y;
        this.params = new DSADomain(p,q,g);
    }

    @Override
    public BigInteger getY() {
        return y;
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
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * X.509 か PKCS#8 か
     * getEncoded() で返す形式
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
    
}
