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

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.ietf.pkcs5.PBES2;
import net.siisise.ietf.pkcs5.PBES2params;
import net.siisise.ietf.pkcs5.PBKDF2params;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;
import net.siisise.security.mac.HMAC;

/**
 * PKCS #8 の後継的な
 * RFC 5208 PKCS #8 Private-Key Information Syntax Specification Version 1.2 私有鍵情報構文仕様 Version 1.2
 * RFC 5958 Asymmetric Key Packages
 */
public class RFC5958 extends PKCS8 {

    /**
     * PBKDF2で使用する乱数生成器のOBJECTIDENTIFIER.
     * HMACが標準、他のMACも設定は可能
     */
    public OBJECTIDENTIFIER prf = HMAC.idhmacWithSHA256;
    /**
     * PBES2で使用する暗号アルゴリズム。
     */
    public OBJECTIDENTIFIER block = AES.AES256_CBC_PAD;
    /**
     * ストレッチ回数。
     */
    public int iterationCount = 2048;

    /**
     * PrivateKeyInfo 暗号付きASN.1符号化.
     *
     * @param keyInfo PKCS #8 PrivateKeyInfo
     * @param pass パスワード
     * @return 暗号化 EncryptedPrivateKeyInfo
     * @throws NoSuchAlgorithmException
     */
    @Override
    EncryptedPrivateKeyInfo encryptPrivateKeyInfo(byte[] keyInfo, byte[] pass) throws NoSuchAlgorithmException {

        SecureRandom srnd = SecureRandom.getInstanceStrong();
        byte[] kdfSalt = new byte[16];
        srnd.nextBytes(kdfSalt);

        Block preBlock = PBES2params.getEncryptionScheme(block);
        byte[] esSalt = null;
        int[] plen = preBlock.getParamLength();
        switch ( plen.length ) { // 1つまで対応可能
            case 1:
                break;
            case 2:
                esSalt = new byte[(plen[1] + 7) / 8]; // IV ブロックサイズに合わせて生成
                srnd.nextBytes(esSalt);
                break;
            default:
                throw new UnsupportedOperationException();
        }

        PBKDF2params kdf2para = new PBKDF2params(kdfSalt, iterationCount, prf);
        PBES2params es2para = new PBES2params(kdf2para, block, esSalt);

        PBES2 es = es2para.decode();
        es.init(pass);
        byte[] encdData = es.encrypt(keyInfo);

        AlgorithmIdentifier es2 = new AlgorithmIdentifier(PBES2.id_PBES2, es2para.encode());
        return new EncryptedPrivateKeyInfo(es2, new OCTETSTRING(encdData));
    }

    /**
     * CMS RFC 5652, RFC 5083 を使って暗号化ができるのでどうにかする.
     * SignedData 署名 EncryptedData
     * AsymmetricKeyで暗号化 暗号化キー共有済み EnvelopedData AsymmetricKeyで暗号化 暗号化キーを共有しない
     * AuthenticatedData メッセージ認証コードを使用して EnvelopedDataと同様な AuthEnvelopedData
     * EnvelopedDataと同様な
     *
     * @param src EncryptedPrivateKeyInfo
     * @param pass password
     * @return PKCS #8 PrivateKeyInfo
     * @throws IOException
     */
    @Override
    public PrivateKeyInfo decryptPrivateKeyInfo(EncryptedPrivateKeyInfo encdInfo, byte[] pass) {
        if (encdInfo.encryptionAlgorithm.algorithm.equals(PBES2.id_PBES2)) {
            PBES2params pbes2params = PBES2params.decode((SEQUENCE) encdInfo.encryptionAlgorithm.parameters);
            PBES2 es = pbes2params.decode();
            es.init(pass);
            byte[] encryptedData = encdInfo.encryptedData.getValue();
            byte[] key = es.decrypt(encryptedData);
            SEQUENCE info = (SEQUENCE) ASN1Util.toASN1(key);
/*
            try {
                System.out.println(ASN1Util.toXMLString(info));
            } catch (Exception ex) {
                throw new IllegalStateException(ex);
            }
*/
            return OneAsymmetricKey.decode(info);
        }
        throw new UnsupportedOperationException();
    }

}
