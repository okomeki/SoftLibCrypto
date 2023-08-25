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

import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.padding.EME_PKCS1_v1_5;

/**
 * RFC 8017 PKCS #1 Section 7. Encryption Schemes
 * 
 * RSAES_PKCS1_v1.5
 * 
 * @deprecated 古い方式. RSAES-OAEP が推奨されている
 */
public class RSAES_v1_5 extends RSAES {

    public RSAES_v1_5() {
        super(new EME_PKCS1_v1_5());
    }

    /**
     * 署名の一般的な拡張(旧式).JWS7515.rsaSign で使ってるかも.
     * @param prv private key
     * @param msg message
     */
    public void sign(RSAMiniPrivateKey prv, byte[] msg) {
//        msg;
        
//        prv.rsasp1(msg);
    }
}
