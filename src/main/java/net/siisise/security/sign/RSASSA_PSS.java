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
import net.siisise.security.digest.XOF;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;
import net.siisise.security.padding.MGF;
import net.siisise.security.padding.MGFXOF;

/**
 * PKCS #1 Section 8.1.
 * MessageDigest、MGF, salt length を初期設定
 * update で本体を渡してから sign または verify をするといい
 * RFC 3447 PKCS #1 v2.1
 * RFC 4055
 * RFC 8702
 */
public class RSASSA_PSS extends RSASSA {
    
    // RFC 8692 8702
    static final String SHAKE128 = "1.3.6.1.5.5.7.6.30";
    static final String SHAKE256 = "1.3.6.1.5.5.7.6.31";
    static final String ecdsaWithShake128 = "1.3.6.1.5.5.7.6.32";
    static final String ecdsaWithShake256 = "1.3.6.1.5.5.7.6.33";
    
    /**
     * とりあえずinitの代わり
     * @param hash hash function
     * @param mgf ちょっと拡張する関数
     * @param sLen salt(乱数生成)のオクテット長
     */
    public RSASSA_PSS(MessageDigest hash, MGF mgf, int sLen) {
        super(new EMSA_PSS(hash, mgf, sLen));
    }

    /**
     * XOF対応版.
     * XOF1と2は同じ型のもの
     * RFC 8702 耐性 最小 SHAKE128 min(d/2,128), SHAKE256 min(d/2,256)
     * SHAKE128( d = 256 ), SHAKE256( d = 512, 
     * @param xof1 ハッシュ用XOF 出力サイズ固定
     * @param xof2 MGF用XOF サイズ可変
     * @param sLen salt(乱数生成)の長さ
     */
    public RSASSA_PSS(XOF xof1, XOF xof2, int sLen) {
        this((MessageDigest)xof1, new MGFXOF(xof2), sLen);
    }

    /**
     * XOF対応 (仮)
     * @param xof
     * @param sLen 
     */
    public RSASSA_PSS(XOF xof, int sLen) {
        this((MessageDigest)xof, new MGFXOF(xof), sLen);
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
