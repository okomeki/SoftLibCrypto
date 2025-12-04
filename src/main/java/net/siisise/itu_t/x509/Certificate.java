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

import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.BITSTRING;
import net.siisise.security.key.RSAMiniPrivateKey;

/**
 * RFC 5280 4.1.1.
 * 署名の形式.
 */
public class Certificate {
    public TBSCertificate tbsCertificate;
    public AlgorithmIdentifier signatureAlgorithm;
    public BITSTRING signatureValue;
    
    /**
     * 仮.
     * @param tbs
     * @param prvKey 秘密鍵
     * @return 
     */
    public static Certificate sign(TBSCertificate tbs, RSAMiniPrivateKey prvKey) {
        Certificate cert = new Certificate();
        cert.tbsCertificate = tbs;
        cert.signatureAlgorithm = tbs.signature;
        
        throw new IllegalStateException();
    }
    
    /**
     * 検証 validate.
     * @param cert 証明書
     * @param pub 公開鍵
     */
    public static void validate(Certificate cert, Object pub) {
        throw new IllegalStateException();
    }
}
