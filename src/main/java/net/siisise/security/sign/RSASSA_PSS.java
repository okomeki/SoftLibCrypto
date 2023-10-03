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
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;
import net.siisise.security.padding.MGF;

/**
 * PKCS #1 Section 8.1.
 * MessageDigest、MGF, salt length を初期設定
 * update で本体を渡してから sign または verify をするといい
 */
public class RSASSA_PSS extends RSASSA {
    
    /**
     * とりあえずinitの代わり
     * @param hash hash function
     * @param mgf ちょっと拡張する関数
     * @param sLen salt(乱数生成)の長さ
     */
    public RSASSA_PSS(MessageDigest hash, MGF mgf, int sLen) {
        super(new EMSA_PSS(hash, mgf, sLen));
    }
    
    /**
     * 署名.
     * 本文はupdateで先に渡す.
     * @param key 秘密鍵
     * @return RSASSA-PSS 署名
     */
    @Override
    public byte[] sign(RSAMiniPrivateKey key) {
        int modBits = key.getModulus().bitLength();
        int k = (modBits + 7) / 8;
//        int ek = (modBits + 6) / 8;
        // (modBits - 1) / 8;
        byte[] EM = emsa.encode(modBits - 1);
        return key.rsasp1(EM,k);
    }
    
    /**
     * 署名検証
     * 8.1.2. Signature Verification Operation
     * 署名を検証する.
     * 本文はupdateで先に渡す.
     * @param pub 公開鍵
     * @param S RSASSA-PSS 署名 signature
     * @return true:有効 / false:無効な署名
     */
    @Override
    public boolean verify(RSAPublicKey pub, byte[] S) {
        int modBits = pub.getModulus().bitLength();
        int k = ( modBits + 7 ) / 8;
        int ek = ( modBits + 6 ) / 8;
        if ( S.length != k) {
            return false;
        }
        try {
            byte[] EM = pub.rsavp1(S, ek);
            return emsa.verify(EM, modBits - 1);
        } catch (SecurityException e) {
            return false;
        }
    }
}
