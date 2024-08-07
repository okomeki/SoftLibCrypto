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

import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;

/**
 * RFC 5208
 * RFC 5958 PKCS #5 系 3. Encrypted Private Key Info
 */
public class EncryptedPrivateKeyInfo {

    public AlgorithmIdentifier encryptionAlgorithm;
    public OCTETSTRING encryptedData;

    public static void decode(SEQUENCE seq) {
        EncryptedPrivateKeyInfo info = new EncryptedPrivateKeyInfo();
        info.encryptionAlgorithm = AlgorithmIdentifier.decode((SEQUENCE) seq.get(0));
        info.encryptedData = (OCTETSTRING) seq.get(1);
    }
}
