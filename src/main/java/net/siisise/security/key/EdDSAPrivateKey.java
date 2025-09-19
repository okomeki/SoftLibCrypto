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
package net.siisise.security.key;

import java.math.BigInteger;
import java.security.PrivateKey;
import java.util.Arrays;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs8.OneAsymmetricKey;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.security.sign.EdDSA;
import net.siisise.security.ec.EdWards;
import net.siisise.security.ec.EdWards25519;

/**
 * EdDSA 秘密鍵.
 *
 */
public class EdDSAPrivateKey implements PrivateKey {

    final EdWards curve;
    byte[] key;
    BigInteger s;
    byte[] prefix;
    byte[] A;

    public EdDSAPrivateKey(byte[] k) {
        this(new EdWards25519(), k);
    }

    /**
     *
     * @param curve 曲線
     * @param k 秘密鍵
     */
    public EdDSAPrivateKey(EdWards curve, byte[] k) {
        this.curve = curve;
        this.key = k.clone();
        byte[] h = curve.H().digest(key);
        int hlen = curve.b / 8;
        byte[] hc = Arrays.copyOfRange(h, 0, hlen);
        s = curve.cuts(hc).mod(curve.L);
        A = curve.nE(s);
        prefix = Arrays.copyOfRange(h, hlen, hlen*2);
    }

    /**
     * ハッシュ化された鍵
     * EdDSAでは乱数の代わりに使われる
     *
     * @return ハッシュ化された秘密鍵
     */
    public byte[] getPrefix() {
        return prefix;
    }

    public BigInteger gets() {
        return s;
    }

    public byte[] getA() {
        return A;
    }

    @Override
    public String getAlgorithm() {
        if (curve.oid.equals(EdDSA.Ed25519)) {
            return "Ed25519";
        } else if (curve.oid.equals(EdDSA.Ed448)) {
            return "Ed448";
        } else if (curve.oid.equals(EdDSA.X25519)) {
            return "X25519";
        } else if (curve.oid.equals(EdDSA.X448)) {
            return "X448";
        }
        throw new IllegalStateException();
    }

    @Override
    public String getFormat() {
        return "EdDSA";
    }

    /**
     * 鍵
     *
     * @return OneAsymmetricKey
     */
    @Override
    public byte[] getEncoded() {
        return rebind(new ASN1DERFormat());
    }

    public byte[] getPKCS8Encoded() {
        ASN1DERFormat af = new ASN1DERFormat();
        OneAsymmetricKey k = new OneAsymmetricKey(curve.oid, rebind(af));
        return k.rebind(af);
    }

    /**
     * PrivateKeyInfo の privateKey PrivateKeyの内側の形式
     *
     * @param <T>
     * @param format
     * @return
     */
    public <T> T rebind(TypeFormat<T> format) {
        OCTETSTRING k = new OCTETSTRING(this.key);
        return k.rebind(format);
    }

    public EdDSAPublicKey getPublicKey() {
        return new EdDSAPublicKey(curve, A);
    }

    public EdWards getCurve() {
        return curve;
    }
}
