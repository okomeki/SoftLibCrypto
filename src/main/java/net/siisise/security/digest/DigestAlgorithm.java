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
package net.siisise.security.digest;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;

/**
 * RFC 8017 PKCS #1 A. と C.
 */
public class DigestAlgorithm extends AlgorithmIdentifier {
    public static final OBJECTIDENTIFIER DIGESTALGORITHM = new OBJECTIDENTIFIER("1.2.840.113549.2");
    /**
     * @deprecated 
     */
    public static final OBJECTIDENTIFIER id_md2 = DIGESTALGORITHM.sub(2);
    /**
     * @deprecated 
     */
    public static final OBJECTIDENTIFIER id_md4 = DIGESTALGORITHM.sub(4);
    /**
     * @deprecated 
     */
    public static final OBJECTIDENTIFIER id_md5 = DIGESTALGORITHM.sub(5);
    // iso(1) identified-organization(3) oiw(14) secsig(3) algorithms(2)
    public static final OBJECTIDENTIFIER algorithms = new OBJECTIDENTIFIER("1.3.14.3.2");
    /**
     * @deprecated 
     */
    public static final OBJECTIDENTIFIER id_sha1 = algorithms.sub(26);
    // joint-iso-itu-t(2) country(16) us(840) organization(1) gov(101) csor(3) nistalgorithm(4) hashAlgs(2)
    public static final OBJECTIDENTIFIER HASHALGS = new OBJECTIDENTIFIER("2.16.840.1.101.3.4.2");
    public static final OBJECTIDENTIFIER id_sha256 = HASHALGS.sub(1);
    public static final OBJECTIDENTIFIER id_sha384 = HASHALGS.sub(2);
    public static final OBJECTIDENTIFIER id_sha512 = HASHALGS.sub(3);
    public static final OBJECTIDENTIFIER id_sha224 = HASHALGS.sub(4);
    public static final OBJECTIDENTIFIER id_sha512_224 = HASHALGS.sub(5);
    public static final OBJECTIDENTIFIER id_sha512_256 = HASHALGS.sub(6);
    
    public static final OBJECTIDENTIFIER id_sha3_224 = HASHALGS.sub(7);
    public static final OBJECTIDENTIFIER id_sha3_256 = HASHALGS.sub(8);
    public static final OBJECTIDENTIFIER id_sha3_384 = HASHALGS.sub(9);
    public static final OBJECTIDENTIFIER id_sha3_512 = HASHALGS.sub(10);

    static final Map<OBJECTIDENTIFIER,String> NAMES = new HashMap<>();
    static final List<OBJECTIDENTIFIER> OAEPPSS;
    static final Map<String,OBJECTIDENTIFIER> OIDS = new HashMap<>();

    static {
        NAMES.put(id_md2, "MD2");
        NAMES.put(id_md4, "MD4");
        NAMES.put(id_md5, "MD5");
        NAMES.put(id_sha1, "SHA1");
        NAMES.put(id_sha224, "SHA-224");
        NAMES.put(id_sha256, "SHA-256");
        NAMES.put(id_sha384, "SHA-384");
        NAMES.put(id_sha512, "SHA-512");
        NAMES.put(id_sha512_224, "SHA-512/224");
        NAMES.put(id_sha512_256, "SHA-512/256");
        NAMES.put(id_sha3_224, "SHA3-224");
        NAMES.put(id_sha3_256, "SHA3-256");
        NAMES.put(id_sha3_384, "SHA3-384");
        NAMES.put(id_sha3_512, "SHA3-512");
        for ( Map.Entry<OBJECTIDENTIFIER, String> e : NAMES.entrySet() ) {
            OIDS.put(e.getValue(), e.getKey());
        }
        OBJECTIDENTIFIER[] oaeppss = {id_sha1, 
        id_sha224,
        id_sha256,
        id_sha384,
        id_sha512,
        id_sha512_224,
        id_sha512_256};
        OAEPPSS = Arrays.asList(oaeppss);
    }

    public static BlockMessageDigest getAlgorithm(OBJECTIDENTIFIER oid) {
        String name;
        name = NAMES.get(oid);
        if ( name == null ) return null;
        return BlockMessageDigest.getInstance(name);
    }
    
    /**
     * EME-OAEP, EMSA-PSS で使えるアルゴリズム
     * @param oid
     * @return 
     */
    public static BlockMessageDigest getOAEPPSSAlgorithm(OBJECTIDENTIFIER oid) {
        if (OAEPPSS.contains(oid)) {
            return getAlgorithm(oid);
        }
        return null;
    }
    
    public static DigestAlgorithm decode(SEQUENCE s) {
        AlgorithmIdentifier alg = AlgorithmIdentifier.decode(s);
        BlockMessageDigest md = getAlgorithm(alg.algorithm);
        if ( md == null ) {
            return null;
        }
        DigestAlgorithm da = new DigestAlgorithm();
        da.algorithm = alg.algorithm;
        da.parameters = alg.parameters;
        return da;
    }

    public static OBJECTIDENTIFIER toOID(MessageDigest md) {
        String name = md.getAlgorithm();
        return OIDS.get(name);
    }
}
