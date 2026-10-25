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
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.security.sign.DSA;

/**
 * DSA秘密鍵.
 * 各フォーマットから取り出すためのものかもしれないが、適度に.
 */
public class DSAPrivateKey implements ASN1PrivateKey, java.security.interfaces.DSAPrivateKey {

    private final BigInteger x;
    private final DSADomain params;

    /**
     * 秘密鍵.
     *
     * @param x private key
     * @param p domain parameter
     * @param q domain parameter
     * @param g domain parameter
     */
    public DSAPrivateKey(BigInteger x, BigInteger p, BigInteger q, BigInteger g) {
        this.x = x;
        params = new DSADomain(p, q, g);
    }

    /**
     * 秘密鍵.
     *
     * @param x private key
     * @param params Domain parameter
     */
    public DSAPrivateKey(BigInteger x, DSAParams params) {
        this.x = x;
        this.params = new DSADomain(params.getP(), params.getQ(), params.getG());
    }

    /**
     * private key.
     * @return private key
     */
    @Override
    public BigInteger getX() {
        return x;
    }

    /**
     * DSA秘密鍵/公開鍵共通部分
     *
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
     *
     * @return
     */
    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * 鍵のみ.
     * @return 
     */
    @Override
    public INTEGER getPrivateKeyASN1() {
        return new INTEGER(x);
    }

    /**
     * INTEGERをはがしてOCTETSTRING に変更?
     * @return 
     */
    @Override
    public OCTETSTRING getPrivateKey() {
        INTEGER i = getPrivateKeyASN1();
        return new OCTETSTRING(i.encodeBody());
    }
    
    /**
     * X.509 PrivateKeyInfo
     * @return 
     */
    @Override
    public byte[] getEncoded() {
        ASN1Tag key = getPrivateKeyASN1();
        return (byte[]) key.rebind(new ASN1DERFormat());
    }

    /**
     * 公開鍵変換.
     * @return 公開鍵
     */
    public DSAPublicKey getPublicKey() {
        return new DSAPublicKey(params.getG().modPow(x, params.getP()), params);
    }

    @Override
    public AlgorithmIdentifier getAlgorithmIdentifier() {
        ASN1Convert format = new ASN1Convert();
        return new AlgorithmIdentifier(DSA.oid, params.rebind(format));
    }

}
