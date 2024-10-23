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

import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.INTEGER;
import net.siisise.security.digest.BlockMessageDigest;
import net.siisise.security.digest.DigestAlgorithm;
import net.siisise.security.digest.SHA1;

/**
 * RSASSA_PSS のパラメータ.
 * SHAKE128 / SHAKE256 の場合は使わない
 */
public class RSASSA_PSS_params {
    
    public static final INTEGER trailerFieldBC = new INTEGER(1);
    /**
     * [0] HashAlgorithm.
     * DEFAULT sha1
     */
    public AlgorithmIdentifier hashAlgorithm = new AlgorithmIdentifier(SHA1.OBJECTIDENTIFIER);
    /**
     * [1] MaskGenAlgorithm
     * DEFAULT mgf1SHA1
     */
    public AlgorithmIdentifier maskGenAlgorithm;
    /**
     * [2] INTEGER
     * DEFAULT 20
     */
    public INTEGER saltLength = new INTEGER(20);
    /**
     * [3] TrailerField
     * DEFAULT trailerFieldBC
     */
    public INTEGER trailerField = trailerFieldBC;

    public RSASSA_PSS decode() {
        BlockMessageDigest alg = DigestAlgorithm.getAlgorithm(hashAlgorithm.algorithm);
//        MGF mgf = 
//        return new RSASSA_PSS(alg);
        throw new UnsupportedOperationException("まだない");
    }
}
