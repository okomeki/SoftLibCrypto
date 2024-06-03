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

/**
 *
 */
public class DSADomainFull extends DSADomain {

    private final BigInteger domainParameterSeed;
    private final BigInteger counter;

    /**
     * 
     * @param p
     * @param q
     * @param g
     * @param domain_parameter_seed 生成用
     * @param counter 生成用
     */
    public DSADomainFull(BigInteger p, BigInteger q, BigInteger g, BigInteger domain_parameter_seed, BigInteger counter) {
        super(p, q, g);
        domainParameterSeed = domain_parameter_seed;
        this.counter = counter;
    }

    public BigInteger getDomainParameterSeed() {
        return domainParameterSeed;
    }

    public BigInteger getCounter() {
        return counter;
    }

}
