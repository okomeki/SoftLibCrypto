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
package net.siisise.itu_t.x509;

import java.math.BigInteger;
import java.util.List;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.annotation.Explicit;
import net.siisise.iso.asn1.annotation.Implicit;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.BITSTRING;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.itu_t.x501.Name;

/**
 * X.509
 * RFC 5280 4.1.1.1. tbsCertificate
 */
public class TBSCertificate {
    @Explicit(tag=0)
    public int version;
    public BigInteger serialNumber;
    public AlgorithmIdentifier signature;
    public Name issuer;
    public Validity validity;
    public Name subject;
    public SubjectPublicKeyInfo subjectPublicKeyInfo;
    @Implicit(tag=1)
    public BITSTRING issuerUniqueID;
    @Implicit(tag=2)
    public BITSTRING subjectUniqueID;
    @Explicit(tag=3)
    public List<Extension> extensions;

    public <T> T rebind(TypeFormat<T> format) {
        SEQUENCEMap cert = new SEQUENCEMap();
        cert.putExplicit("version", 0, new INTEGER(version));
        cert.put("serialNumber", serialNumber);
        cert.put("signature", signature);
        cert.put("issuer", issuer);
        cert.put("validity",validity);
        cert.put("subject", subject);
        cert.put("subjectPublicKeyInfo", subjectPublicKeyInfo);
        if ( issuerUniqueID != null ) {
            cert.putImplicit("issuerUniqueID", 1, issuerUniqueID);
        }
        if ( subjectUniqueID != null ) {
            cert.putImplicit("subjectUniqueID", 2, subjectUniqueID);
        }
        if ( extensions != null && !extensions.isEmpty() ) {
            ASN1Convert a1c = new ASN1Convert();
            cert.putExplicit("extensions", 3, a1c.listFormat(extensions));
        }
        return (T)cert.rebind(format);
    }

}
