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

import java.util.LinkedHashMap;
import net.siisise.bind.format.TypeFormat;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCEMap;
import net.siisise.security.digest.DigestAlgorithm;

/**
 * RFC 8017 RSA
 * A.2.4 RSASSA-PKCS-v1_5
 * 署名内の格納形式
 */
public class DigestInfo {
    public DigestAlgorithm digestAlgorithm;
    public OCTETSTRING digest;

    public DigestInfo(DigestAlgorithm algorithm, OCTETSTRING digest) {
        digestAlgorithm = algorithm;
        this.digest = digest;
    }

    public DigestInfo(DigestAlgorithm algorithm, byte[] digest) {
        digestAlgorithm = algorithm;
        this.digest = new OCTETSTRING(digest);
    }
    
    public SEQUENCEMap encodeASN1() {
        return (SEQUENCEMap)rebind(new ASN1Convert());
    }
    
    public <V> V rebind(TypeFormat<V> format) {
        LinkedHashMap seq = new LinkedHashMap();
        seq.put("digestAlgorithm", digestAlgorithm);
        seq.put("digest", digest);
        return format.mapFormat(seq);
    }
}
