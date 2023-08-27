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
package net.siisise.security.sign;

import java.security.MessageDigest;
import net.siisise.security.digest.SHA1;
import net.siisise.security.padding.EME_OAEP;

/**
 * RFC 8017 PKCS #1
 * Section 7. 暗号化スキーム Encryption Schemes
 * 
 * Section 5.1.1. RSAEP, Section 5.1.2. RSADP
 * 
 * 7.1. RSAES-OAEP
 * Scction 7.1.1. Step 2, 7.1.2. Step 3 EME-OAEP
 * 
 * IEEE 1363 IFES
 * IFES-RSA
 * IFDP-RSA
 * EME-OAEP
 * 
 * RSAES-OAEP 最大 k-2hLen-2 octet
 * hLen 
 */
public class RSAES_OAEP extends RSAES {
    
    /**
     * いろいろな初期値.
     * L ラベルは PKCS #1 v2.2 では使用しないのでコンストラクタからは外す形
     * @param md L用 DEFAULT sha1
     * @param mgfMd MGF用 DEFAULT mgf1SHA1
     */
    public RSAES_OAEP(MessageDigest md, MessageDigest mgfMd) {
        super(new EME_OAEP(mgfMd, md));
    }
    
    /**
     * ラベルはOption
     * @param L label (Optional)
     */
    public void updateLabel(byte[] L) {
        ((EME_OAEP)eme).updateLabel(L);
    }

    /**
     * 
     * @param md L用とMGF用兼用 省略時 SHA1
     */
    public RSAES_OAEP(MessageDigest md) {
        this(md, md);
    }

    public RSAES_OAEP() {
        this(new SHA1());
    }
}
