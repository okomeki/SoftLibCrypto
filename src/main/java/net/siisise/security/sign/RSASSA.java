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
import net.siisise.security.key.RSAPublicKey;

/**
 * RFC 8017 PKCS #1 Section 8. Signature Scheme with Appendix
 * modulus より長いデータの署名に向いている
 * https://www.cryptrec.go.jp/en/cryptrec_03_spec_cypherlist_files/PDF/pkcs-1v2-12.pdf
 */
public abstract class RSASSA {
    EMSA emsa;
    
    public void update(byte[] M) {
        emsa.update(M);
    }
    
    public void update(byte[] M, int offset, int length) {
        emsa.update(M, offset, length);
    }

    /**
     * 署名
     * @param key 秘密鍵
     * @param M メッセージ
     * @return 署名
     */
    public byte[] sign(RSAMiniPrivateKey key, byte[] M) {
        update(M);
        return sign(key);
    }
    
    public abstract byte[] sign(RSAMiniPrivateKey key);
    
    /**
     * 検証
     * @param pub 公開鍵
     * @param M メッセージ
     * @param S 署名
     * @return 判定
     */
    public boolean verify(RSAPublicKey pub, byte[] M, byte[] S) {
        update(M);
        return verify(pub, S);
    }

    public abstract boolean verify(RSAPublicKey pub, byte[] S);
}
