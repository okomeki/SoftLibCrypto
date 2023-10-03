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

import java.nio.ByteBuffer;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPrivateCrtKey;
import net.siisise.security.key.RSAPublicKey;

/**
 * RFC 8017 PKCS #1 Section 8. Signature Scheme with Appendix
 * modulus より長いデータの署名に向いている
 * https://www.cryptrec.go.jp/en/cryptrec_03_spec_cypherlist_files/PDF/pkcs-1v2-12.pdf
 */
public abstract class RSASSA implements SignVerify {
    final EMSA emsa;
    private RSAMiniPrivateKey skey;
    private RSAPublicKey pkey;
    
    RSASSA(EMSA emsa) {
        this.emsa = emsa;
    }
    
    /**
     * 秘密鍵の事前設定.
     * @param key 秘密鍵
     * @return 
     */
    public RSASSA init(RSAMiniPrivateKey key) {
        skey = key;
        if ( key instanceof RSAPrivateCrtKey ) {
            pkey = ((RSAPrivateCrtKey) key).getPublicKey();
        }
        return this;
    }
    
    public RSASSA init(RSAPublicKey key) {
        pkey = key;
        return this;
    }

    /**
     * 仮.
     * @return 
     */
    @Override
    public int getKeyLength() {
        return 2048;
    }

    /**
     * 署名/検証用メッセージをハッシュにかける.
     * MessageDigestのupdateと同じ
     * 本文を分割して繰り返し利用可能.
     * @param M メッセージまたはその一部
     */
    @Override
    public void update(byte[] M) {
        emsa.update(M);
    }
    
    /**
     * 署名/検証用メッセージをハッシュにかける.
     * MessageDigestのupdateと同じ
     * 本文を分割して繰り返し利用可能.
     * @param M メッセージを含む配列
     * @param offset 開始位置
     * @param length 長さ
     */
    @Override
    public void update(byte[] M, int offset, int length) {
        emsa.update(M, offset, length);
    }

    /**
     * 署名/検証用メッセージをハッシュにかける.
     * MessageDigestのupdateと同じ
     * 本文を分割して繰り返し利用可能.
     * 
     * @param buffer メッセージを含むBuffer
     */
    public void update(ByteBuffer buffer) {
        emsa.update(buffer);
    }
    
    /**
     * 署名
     * @param key 秘密鍵
     * @param M メッセージ (updateを使っている場合は末尾に当たる部分)
     * @return 署名
     */
    public byte[] sign(RSAMiniPrivateKey key, byte[] M) {
        update(M);
        return sign(key);
    }
    
    /**
     * 署名.
     * メッセージは事前にupdateを使用してハッシュ関数に渡す.
     * @param key 秘密鍵
     * @return 署名
     */
    public abstract byte[] sign(RSAMiniPrivateKey key);

    /**
     * 署名.
     * @return 署名 signature
     */
    @Override
    public byte[] sign() {
        return sign(skey);
    }
    
    /**
     * 検証
     * @param pub 公開鍵
     * @param M メッセージ (updateを使っている場合は末尾に当たる部分)
     * @param S 署名 signature
     * @return 判定 true false
     */
    public boolean verify(RSAPublicKey pub, byte[] M, byte[] S) {
        update(M);
        return verify(pub, S);
    }

    /**
     * 検証.
     * メッセージは事前にupdateを使用してハッシュ関数に渡す.
     * @param pub 公開鍵
     * @param S 署名 signature
     * @return 判定 true false
     */
    public abstract boolean verify(RSAPublicKey pub, byte[] S);

    /**
     * 検証.
     * @param S 署名 signature
     * @return 判定
     */
    @Override
    public boolean verify(byte[] S) {
        return verify(pkey, S);
    }
}
