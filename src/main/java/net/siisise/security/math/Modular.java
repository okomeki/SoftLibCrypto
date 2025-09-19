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
package net.siisise.security.math;

import java.math.BigInteger;

/**
 * Modular.
 * 合同算術. モジュラ演算など 素数系
 */
public class Modular {

    BigInteger p;
    public BigInteger val;

    public Modular(BigInteger p) {
        this.p = p;
    }

    public Modular(BigInteger v, BigInteger p) {
        this.p = p;
        val = v;
    }
    
    public boolean equals(Modular m) {
        return p.equals(m.p) && val.equals(m.val);
    }

    public Modular val(BigInteger v) {
        return new Modular(v.mod(p), p);
    }

    public Modular add(BigInteger v) {
        BigInteger r = val.add(v);
        return new Modular(r.compareTo(p) > 0 ? r.subtract(p) : r, p);
    }

    public Modular add(Modular v) {
        BigInteger r = val.add(v.val);
        return new Modular(r.compareTo(p) > 0 ? r.subtract(p) : r, p);
    }

    public BigInteger add(BigInteger a, BigInteger b) {
        BigInteger r = a.add(b);
        return r.compareTo(p) > 0 ? r.subtract(p) : r;
    }

    public Modular sub(BigInteger v) {
        BigInteger r = val.subtract(v);
        return new Modular(val.compareTo(v) < 0 ? r.add(p) : r, p);
    }

    public Modular sub(Modular v) {
        BigInteger r = val.subtract(v.val);
        return new Modular(val.compareTo(val) < 0 ? r.add(p) : r, p);
    }

    public BigInteger sub(BigInteger a, BigInteger b) {
        BigInteger r = a.subtract(b);
        return a.compareTo(b) < 0 ? r.add(p) : r;
    }
    
    public Modular negate() {
        return new Modular(p.subtract(val), p);
    }

    public Modular mul(BigInteger v) {
        return new Modular(val.multiply(v).mod(p), p);
    }

    public Modular mul(Modular v) {
        return new Modular(val.multiply(v.val).mod(p), p);
    }

    public Modular mul(BigInteger a, BigInteger b) {
        return new Modular(a.mod(p).multiply(b.mod(p)).mod(p), p);
    }

    public Modular pow(BigInteger v) {
        return new Modular(val.modPow(v, p), p);
    }

    public Modular pow(long v) {
        return pow(BigInteger.valueOf(v));
    }

    public Modular div(BigInteger v) {
        return new Modular(val.multiply(v.modInverse(p)).mod(p), p);
    }

    public Modular div(Modular v) {
        return new Modular(val.multiply(v.val.modInverse(p)).mod(p), p);
    }

    public BigInteger div(BigInteger a, BigInteger b) {
        return a.multiply(b.modInverse(p)).mod(p);
    }
    
    public Modular inv() {
        return new Modular(val.modInverse(p),p);
    }
}
