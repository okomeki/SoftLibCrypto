/*
 * Copyright 2022 okome.
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
package net.siisise.ietf.pkcs5;

import java.util.Arrays;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.security.block.Block;
import net.siisise.security.mac.MAC;
import net.siisise.security.mode.PKCS7Padding;

/**
 * RFC 8018 PKCS #5
 * Section 6.2. PBES2
 *
 */
public class PBES2 implements PBES {
    public static final OBJECTIDENTIFIER id_PBES2 = PBKDF2.PKCS5.sub(13);
    private final PBKDF2 kdf;
    private Block block;
    
    public PBES2(PBKDF2 kdf) {
        this.kdf = kdf;
    }

    public PBES2(MAC hmac) {
        this(new PBKDF2(hmac));
    }
    
    public PBES2() {
        kdf = new PBKDF2();
    }
    
    /**
     * hmac は設定済みのものを使う版.
     * password, salt, c から dk を作って block を初期化する.
     * 
     * @param block XXX-CBC
     * @param password password
     * @param salt salt
     * @param c iteration count
     * @return 
     */
    public Block init(Block block, byte[] password, byte[] salt, int c) {
//        digest.getDigestLength();
        int[] nlen = block.getParamLength();
        int[] blen = new int[nlen.length];
        for (int i = 0; i < nlen.length; i++ ) {
            blen[i] = (nlen[i] + 7) / 8;
        }
        
        kdf.init(salt,c);
//        kdf.init(hmac);
        byte[][] dk = kdf.pbkdf(password, blen);
        block.init(dk); // k, iv
        this.block = block;
        return block;
    }
    
    /**
     * 
     * @param block XXX-CBC
     * @param hmac
     * @param password password
     * @param salt salt
     * @param c iteration count
     * @return 
     */
    public Block init(Block block, MAC hmac, byte[] password, byte[] salt, int c) {
//        digest.getDigestLength();
        int[] nlen = block.getParamLength(); // ビット
        int[] blen = new int[nlen.length]; // バイト
        for ( int i = 0; i < nlen.length; i++ ) {
            blen[i] = (nlen[i] + 7) / 8;
        }
        kdf.init(hmac, salt, c);
        // hmac.init();
        byte[][] dk = kdf.pbkdf(password, blen);
        block.init(dk); // k, iv
        this.block = block;
        return block;
    }

    /**
     * PBES2params から生成したあとパスワードだけ
     * @param block
     * @param password 
     */
    public void init(Block block, byte[] password) {
        throw new java.lang.UnsupportedOperationException("まだない");
    }
    
    public void init(byte[] password) {
        int[] ps = block.getParamLength();
        int[] bs = new int[ps.length];
        int s = 0;
        for (int p : ps) {
            s += (p + 7) / 8;
        }
        byte[] ll = kdf.kdf(password, s);
        s = (ps[0] + 7) / 8;
        byte[] key = Arrays.copyOfRange(ll, 0, s);
        byte[] iv = Arrays.copyOfRange(ll, s, s + (ps[1] + 7) / 8);
        block.init(key, iv);
    }

    /**
     * 
     * @param seq OID次のパラメータ
     */
    public void setASN1(SEQUENCE seq) {
        
        if ( seq.get(0,0).equals(PBKDF2.OID)) {
            kdf.setASN1Params((SEQUENCE) seq.get(0,1));
        } else {
            throw new IllegalStateException();
        }
    }

    /**
     * メッセージ1つを暗号化する.
     * 
     * @param message 
     * @return ブロック長にpaddingされたメッセージの暗号
     */
    @Override
    public byte[] encrypt(byte[] message) {
        PKCS7Padding pad = new PKCS7Padding(block);
        return pad.doFinalEncrypt(message);
    }

    /**
     * 
     * @param message 暗号
     * @return 元メッセージ
     */
    @Override
    public byte[] decrypt(byte[] message) {
        PKCS7Padding pad = new PKCS7Padding(block);
        return pad.doFinalDecrypt(message);
    }

    void setBlock(Block encryptionScheme) {
        this.block = encryptionScheme;
//        block.init(keyandparam);
    }
}
