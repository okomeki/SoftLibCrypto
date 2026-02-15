/*
 * Copyright 2025 okome.
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
package net.siisise.security.key;

import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.ietf.pkcs8.OneAsymmetricKey;
import net.siisise.ietf.pkcs8.PrivateKeyInfo;
import net.siisise.iso.asn1.ASN1Tag;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.iso.asn1.tag.OCTETSTRING;

/**
 * PrivateKeyの各種形式.
 * 
 * PKCS #8 の PrivateKey ;;= OCTETSTRING.
 * 
 * OneAsymmetricKey っぽい方に変更
 */
public interface ASN1PrivateKey {

    /**
     * 鍵の形式と符号化の組み合わせ
     */
    public static enum Format {
        PrivateKey, // 各鍵のASN.1固有DER形式
//        PrivateKeyOCTET, // 各鍵の固有形式をPrivateKeyInfo用にOCTETSTRINGに梱包したもの
        PrivateKeyInfo, // PKCS #8
        EncryptedPrivateKeyInfo, // PKCS #8
        OneAsymmetricKey, // PKCS #8 拡張 RFC 5958
//        PrivateKeyPEM, // 旧形式
//        PrivateKeyEncryptedPEM, // 旧形式+パスワードPBES1 暗号化 テキスト
        PrivateKeyInfoPEM, // PKCS #8 テキスト
        EncryptedPrivateKeyInfoPEM // PKCS #8 PBES2 暗号化 テキスト
    }

    /**
     * 公開鍵側OIDと同じでいいかも.
     * @return 
     */
    AlgorithmIdentifier getAlgorithmIdentifier();

    /**
     * PKCS #8格納用のprivateKey 部分相当.
     * PrivateKey ::= OCTET STRING
     * OCTETSTRING版
     * RSAのSEQUENCEなどの場合はDER符号化後OCTETSTREAMにパッケージする
     * @return privateKey OCTETSTRING
     */
    OCTETSTRING getPrivateKey();

    /**
     * PrivateKey 符号化前.
     * SEQUENCE など原型
     * 
     * @return ASN1Tagのまま
     */
    ASN1Tag getPrivateKeyASN1();

    default PrivateKeyInfo getPrivateKeyInfo() {
        AlgorithmIdentifier ai = getAlgorithmIdentifier();
        byte[] body = (byte[]) getPrivateKey().rebind(new ASN1DERFormat()); // privateKey PrivateKey (BER / RFC 5208)
        return new PrivateKeyInfo(ai, body);
    }
    
    default OneAsymmetricKey getOneAsymmetricKey() {
        AlgorithmIdentifier ai = getAlgorithmIdentifier();
        byte[] body = (byte[]) getPrivateKey().rebind(new ASN1DERFormat()); // privateKey PrivateKey (BER / RFC 5208)
        return new OneAsymmetricKey(ai, body);
    }

}
