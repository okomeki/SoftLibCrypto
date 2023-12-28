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
package net.siisise.security.sign;

import java.math.BigInteger;
import java.security.interfaces.DSAParams;

/**
 * DSA ドメインパラメータ
 */
public class DSADomain implements DSAParams {

    BigInteger p;
    BigInteger q;
    BigInteger g;

    /**
     *
     * @param p
     * @param q
     * @param g
     */
    public DSADomain(BigInteger p, BigInteger q, BigInteger g) {
        this.p = p;
        this.q = q;
        this.g = g;
    }

    @Override
    public BigInteger getP() {
        return p;
    }

    @Override
    public BigInteger getQ() {
        return q;
    }

    @Override
    public BigInteger getG() {
        return g;
    }
}
