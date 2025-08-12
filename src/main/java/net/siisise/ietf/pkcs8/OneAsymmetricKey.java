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
package net.siisise.ietf.pkcs8;

import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.ASN1;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.BITSTRING;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 5958 OneAsymmetricKey [v2].
 * 
 * OneAsymmetricKey ::= SEQUENCE {
 *   version Version,
 *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *   privateKey PrivateKey,
 *   attributes [0] Attributes OPTIONAL,
 *   ...,
 *   [[2: publicKey [1] PublicKey OPTIONAL ]],
 *   ... }
 *
 * v1相当 RFC 5208
 * PrivateKeyInfo ::= SEQUENCE {
 *   version Version,
 *   privateKeyAlgorithm PrivateKeyAlgorithmIdentifier,
 *   privateKey PrivateKey,
 *   attributes [0] IMPLICIT Attributes OPTIONAL } }
 *
 *
 * RFC 5208 PrivateKeyInfo [v1]
 */
public class OneAsymmetricKey extends PrivateKeyInfo {

    public static final OBJECTIDENTIFIER id_ct_KP_aKeyPackage = new OBJECTIDENTIFIER("2.16.840.1.101.2.1.2.78.5");

    static enum Version {
        v1(0),
        v2(1);
        INTEGER n;

        Version(int n) {
            this.n = new INTEGER(n);
        }

        INTEGER value() {
            return n;
        }
    }

    public OneAsymmetricKey() {
    }

    /**
     *
     * @param oid Object Identifier RFC 8410 9295
     * @param privateKey 秘密鍵
     */
    public OneAsymmetricKey(OBJECTIDENTIFIER oid, byte[] privateKey) {
        super(oid, privateKey);
    }

    public OneAsymmetricKey(AlgorithmIdentifier ai, byte[] privateKey) {
        super(ai, privateKey);
    }

    /**
     * 公開鍵.
     * 
     */
    public byte[] publicKey; // [1] PublicKey OPTIONAL

    /**
     * version 指定を優先、公開鍵がない場合はv1固定。
     *
     * @return
     */
    @Override
    public SEQUENCEMap encodeASN1() {
        SEQUENCEMap one = new SEQUENCEMap();
        // version 0: 秘密鍵のみ　version 1: 公開鍵込み
        if (publicKey == null) {
            one.put("version", Version.v1.value());
        } else {
            one.put("version", version);
        }
        one.put("privateKeyAlgorithm", privateKeyAlgorithm);
        one.put("privateKey", privateKey);
        if (attributes != null && !attributes.isEmpty()) {
            //ASN1Prefixed pre0 = new ASN1Prefixed(0, Rebind.valueOf(attributes, new ASN1Convert()));
            SEQUENCE pre0 = (SEQUENCE) Rebind.valueOf(attributes, new ASN1Convert());
            pre0.setContextSpecific(0);
            one.put("attributes", pre0);
        }
        if (publicKey != null && version > 0) { // IMPLICIT
            BITSTRING pre1 = new BITSTRING( publicKey);
            one.putImplicit("publicKey", 1, pre1);
        }
        return one;
    }

    /**
     * OneAsymmetricKeyの符号化
     * @param <V> 出力型
     * @param format 出力形式
     * @return 符号化
     */
    @Override
    public <V> V rebind(TypeFormat<V> format) {
        SEQUENCEMap map = new SEQUENCEMap();
        map.put("version", version);
        map.put("privateKeyAlgorithm", privateKeyAlgorithm);
        map.put("privateKey", privateKey);

        if (attributes != null && !attributes.isEmpty()) {
            map.putExplicit("attributes", 0, Rebind.valueOf(attributes, new ASN1Convert()));
        }

        if (publicKey != null && version >= 1) { // IMPLICIT
            BITSTRING pre1 = new BITSTRING( publicKey);
            map.putImplicit("publicKey", 1, pre1);
        }
        return (V)map.rebind(format); //Rebind.valueOf(map, format);
    }

    /**
     * ToDo: overflow
     *
     * @param s
     * @return
     */
    public static PrivateKeyInfo decode(SEQUENCE s) {
        INTEGER ver = (INTEGER) s.get(0);
        long longVer = ver.longValue();
        if (longVer == 1) {
            OneAsymmetricKey key = new OneAsymmetricKey();
            key.version = ver.intValueExact();
            key.privateKeyAlgorithm = AlgorithmIdentifier.decode((SEQUENCE) s.get(1));
            key.privateKey = ((OCTETSTRING) s.get(2)).getValue();
            key.publicKey = ((BITSTRING) s.getContextSpecific(0, ASN1.BITSTRING)).getValue();
            return key;
        } else {
            return PrivateKeyInfo.decode(s);
        }
    }
}
