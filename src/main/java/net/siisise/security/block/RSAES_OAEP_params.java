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
package net.siisise.security.block;

import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.iso.asn1.ASN1;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.ASN1Prefixed;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.security.digest.BlockMessageDigest;
import net.siisise.security.digest.DigestAlgorithm;
import net.siisise.security.digest.SHA1;
import net.siisise.security.padding.MGF1;

/**
 * RFC 8017 A.2.1
 */
public class RSAES_OAEP_params {

    public AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(SHA1.OBJECTIDENTIFIER);
    public AlgorithmIdentifier maskGenAlgorithm = new AlgorithmIdentifier(MGF1.OID, ASN1Util.toASN1(new AlgorithmIdentifier(SHA1.OBJECTIDENTIFIER)));
    public AlgorithmIdentifier pSourceAlgorithm = new AlgorithmIdentifier(PKCS1.id_pSpecified, new OCTETSTRING());

    public <T> T rebind(TypeFormat<T> format) {
        return (T)encode().rebind(format);
    }

    public SEQUENCEMap encode() {
        SEQUENCEMap seq = new SEQUENCEMap();
        if ( !hashAlgorithm.algorithm.equals(SHA1.OBJECTIDENTIFIER)) {
            seq.put("hashAlgorithm", new ASN1Prefixed(0, hashAlgorithm.encodeASN1()));
        }
//        if ( !maskGenAlgorithm.algorithm.equals(MGF1.OID)) {
            seq.put("maskGenAlgorithm", new ASN1Prefixed(1, maskGenAlgorithm.encodeASN1()));
//        }
        if ( !pSourceAlgorithm.algorithm.equals(PKCS1.id_pSpecified)) {
            seq.put("pSourceAlgorithm", new ASN1Prefixed(2, pSourceAlgorithm.encodeASN1()));
        }
        return seq;
    }

    public void decode(SEQUENCE seq) {
        SEQUENCE s = (SEQUENCE) seq.getContextSpecific("hashAlgorithm", 0, ASN1.SEQUENCE);
        if (s != null) {
            hashAlgorithm = AlgorithmIdentifier.decode(s);
        } else {
            hashAlgorithm = new AlgorithmIdentifier(SHA1.OBJECTIDENTIFIER);
        }
        s = (SEQUENCE) seq.getContextSpecific("hashGenAlgorithm", 1, ASN1.SEQUENCE);
        if (s != null) {
            maskGenAlgorithm = AlgorithmIdentifier.decode(s);
        } else {
            maskGenAlgorithm = new AlgorithmIdentifier(MGF1.OID);
        }
        s = (SEQUENCE) seq.getContextSpecific("pSourceAlgorithm", 2, ASN1.SEQUENCE);
        if ( s != null) {
            pSourceAlgorithm = AlgorithmIdentifier.decode(s);
        } else {
            pSourceAlgorithm = new AlgorithmIdentifier(PKCS1.id_pSpecified, new OCTETSTRING());
        }
    }
    
    public RSAES_OAEP decode() {
        BlockMessageDigest digest = DigestAlgorithm.getAlgorithm(hashAlgorithm.algorithm);
        BlockMessageDigest mgfalg = DigestAlgorithm.getAlgorithm(AlgorithmIdentifier.decode((SEQUENCE) maskGenAlgorithm.parameters).algorithm);
        return new RSAES_OAEP(digest, mgfalg);
    }
    
}
