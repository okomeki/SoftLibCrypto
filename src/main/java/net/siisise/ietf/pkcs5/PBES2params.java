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
package net.siisise.ietf.pkcs5;

import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.security.block.Block;

/**
 *
 */
public class PBES2params {
    public AlgorithmIdentifier keyDerivationFunc;
    public AlgorithmIdentifier encryptionScheme;

    public static PBES2params decode(SEQUENCE s) {
        PBES2params params = new PBES2params();
        params.keyDerivationFunc = AlgorithmIdentifier.decode((SEQUENCE) s.get(0));
        params.encryptionScheme = AlgorithmIdentifier.decode((SEQUENCE) s.get(1));
        return params;
    }
    
    public PBES2 decode() {
        PBES2 es;
        Block block;
        if ( keyDerivationFunc.algorithm.equals(PBKDF2.OID)) {
            PBKDF2 kdf = PBKDF2params.decode((SEQUENCE) keyDerivationFunc.parameters).decode();
            es = new PBES2(kdf);
        } else {
            throw new UnsupportedOperationException(keyDerivationFunc.algorithm.toString());
        }
        es.setBlock(getEncryptionScheme());
        return es;
    }
    
    public Block getEncryptionScheme() {
        // B.2.2. DES-EDE3-CBC-Pad
        // RFC 1423 Padding
        //       24 octet encryption keey
        // param CBC 8 byte ぐらい initialization vector
        
        // B.2.3. RC2-CBC-Pad
        // RFC 2268
        // param 1-128 octet 鍵
        //       1-1024 bit effective key bits
        //       8 octet initicalization vector
        
        
        System.out.println("encryptionScheme:" + encryptionScheme.algorithm.toString());
        throw new UnsupportedOperationException("encryptionScheme:" + encryptionScheme.algorithm.toString());
    }
}
