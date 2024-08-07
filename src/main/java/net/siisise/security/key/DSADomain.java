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
import java.util.ArrayList;
import java.util.List;
import net.siisise.bind.Rebind;
import net.siisise.iso.asn1.tag.ASN1DERFormat;

/**
 * DSA ドメインパラメータ
 * FIPS PUB 186-4 Section 4
 */
public class DSADomain implements DSAParams {

    private final BigInteger p;
    private final BigInteger q;
    private final BigInteger g;

    /**
     * 
     * @param p 付録 A.1
     * @param q 付録 A.1
     * @param g ジェネレータ 付録 A.2
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

    /**
     * ジェネレータ
     * @return 
     */
    @Override
    public BigInteger getG() {
        return g;
    }
    
    public byte[] getEncoded() {
        List l = new ArrayList();
        l.add(p);
        l.add(q);
        l.add(g);
        return Rebind.valueOf(l, new ASN1DERFormat());
        
    }
}
