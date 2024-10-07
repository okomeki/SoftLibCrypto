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

import java.util.LinkedHashMap;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.ASN1Convert;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.iso.asn1.tag.SEQUENCEMap;

/**
 * RFC 5208
 * RFC 5958 PKCS #5 系
 * 3. Encrypted Private Key Info
 */
public class EncryptedPrivateKeyInfo {

    /**
     * PBES2 想定.
     */
    public AlgorithmIdentifier encryptionAlgorithm;
    /**
     * 暗号化されたPrivateKeyInfo
     */
    public OCTETSTRING encryptedData;

    /**
     * 
     * @param ea 暗号アルゴリズム
     * @param data 暗号データ
     */
    EncryptedPrivateKeyInfo(AlgorithmIdentifier ea, OCTETSTRING data) {
        encryptionAlgorithm = ea;
        encryptedData = data;
    }

    /**
     * ASN.1 DER deocde
     * @param seq DER format EncryptedPrivateInfo
     * @return EncryptedPrivateKeyInfo
     */
    public static EncryptedPrivateKeyInfo decode(SEQUENCE seq) {
        if (seq.size() == 2) {
            AlgorithmIdentifier alg = AlgorithmIdentifier.decode((SEQUENCE) seq.get(0));
            return new EncryptedPrivateKeyInfo(alg, (OCTETSTRING) seq.get(1));
        }
        throw new IllegalStateException();
    }

    public SEQUENCEMap decode() {
        return (SEQUENCEMap)rebind(new ASN1Convert());
    }
    
    public <V> V rebind(TypeFormat<V> format) {
        LinkedHashMap info = new LinkedHashMap();
        info.put("encryptionAlgorithm", encryptionAlgorithm.rebind(format));
        info.put("encryptedData", encryptedData);
        return format.mapFormat(info); //Rebind.valueOf(info, format);
    }
}
