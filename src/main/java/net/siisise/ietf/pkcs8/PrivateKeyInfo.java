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
package net.siisise.ietf.pkcs8;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.List;
import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.ASN1Cls;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEList;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * PKCS #8 PrivateKeyInfo.
 * PEMヘッダ PRIVATE KEY
 * RFC 5208 PKCS #8 5. Private-Key Information Syntax
 * RFC 5958
 * 
 * RSA, ECDSA など
 * 
 */
public class PrivateKeyInfo {
//    static class Version extends INTEGER {}
    
//    static class Attributes extends SEQUENCEList {}

    /**
     * version Version
     * 
     * Version ::= INTEGER
     */
    public int version;

    /**
     * privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
     * 鍵種別、オプション。
     * OIDは秘密鍵用がないので公開鍵のものが使われる
     * PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
     */
    public AlgorithmIdentifier privateKeyAlgorithm;

    /**
     * privateKey PrivateKey
     * 秘密鍵.
     * PrivateKey ::= OCTET STRING
     */
    public byte[] privateKey;
    /**
     * attributes [0] IMPLICIT Attributes OPTIONAL
     * Attributes ::= SET OF Attribute
     */
    List attributes;

    public PrivateKeyInfo() {
    }

    /**
     * 秘密鍵.
     * OIDは公開鍵相当のものを指定するのかも.
     * @param algorithm 鍵種別
     * @param privateKey 秘密鍵
     */
    public PrivateKeyInfo(AlgorithmIdentifier algorithm, byte[] privateKey) {
        version = 0;
        privateKeyAlgorithm = algorithm;
        this.privateKey = privateKey;
    }

    /**
     * 秘密鍵.
     * OIDは公開鍵相当のものを指定するのかも.
     * @param oid 鍵種別 パラメータ省略 AlgorithmIdentifier
     * @param privateKey 秘密鍵
     */
    public PrivateKeyInfo(OBJECTIDENTIFIER oid, byte[] privateKey) {
        this(new AlgorithmIdentifier(oid), privateKey);
    }

    /**
     * 汎用出力.
     * @param <T> 
     * @param format 出力型
     * @return 
     */
    public <T> T rebind(TypeFormat<T> format) {
        LinkedHashMap s = new LinkedHashMap();
        s.put("version", version);
        s.put("privateKeyAlgorithm", privateKeyAlgorithm);
        s.put("privateKey", privateKey);
        if (attributes != null && !attributes.isEmpty()) {
            SEQUENCEList atrs = new SEQUENCEList(ASN1Cls.CONTEXT_SPECIFIC, 0); // SET OF
            atrs.addAll(Rebind.valueOf(attributes, ASN1Tag.class));
            s.put("attributes", atrs);
        }
        return Rebind.valueOf(s,format);
    }

    /**
     * ASN.1出力.
     * @return ASN.1型
     */
    public SEQUENCEMap encodeASN1() {
        return (SEQUENCEMap)rebind(new ASN1Convert());
    }

    /**
     * ASN.1型の読み込み.
     * version=0 想定.
     * version=1はOneAsymmetricKey
     * algorithm と privateKey を持つ.
     * @param seq　ASN.1型
     * @return PrivateKeyInfo
     */
    public static PrivateKeyInfo decode(SEQUENCE seq) {
        INTEGER ver = (INTEGER) seq.get(0);
        AlgorithmIdentifier privateKeyAlg = AlgorithmIdentifier.decode((SEQUENCE) seq.get(1));
        if ( ver.getValue().equals(BigInteger.ZERO)) {
            PrivateKeyInfo info = new PrivateKeyInfo(privateKeyAlg, ((OCTETSTRING)seq.get(2)).getValue());
            if (seq.size() == 3) {
                return info;
            }
        }
        throw new UnsupportedOperationException();
    }
}
