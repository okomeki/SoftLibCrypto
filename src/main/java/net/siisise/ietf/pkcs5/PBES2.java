/*
 * Copyright 2022-2024 okome.
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
import net.siisise.security.block.Block;
import net.siisise.security.mac.MAC;

/**
 * RFC 8018 PKCS #5
 * Section 6.2. PBES2
 * A.4. PBES2
 */
public class PBES2 implements PBES {
    public static final OBJECTIDENTIFIER id_PBES2 = PBKDF2.PKCS5.sub(13);
    private final PBKDF2 kdf;
    private Block block;
    // 1つなので仮
    private byte[][] params;

    /**
     * PBKDF2を指定して初期化.
     * @param kdf PBKDF2
     */
    public PBES2(PBKDF2 kdf) {
        this.kdf = kdf;
    }

    /**
     * MACアルゴリズムを指定して初期化.
     * @param hmac PBKDF2用疑似乱数関数 MAC PRF
     */
    public PBES2(MAC hmac) {
        this(new PBKDF2(hmac));
    }

    /**
     * 標準設定で初期化.
     * PBKDF2(HMAC-SHA1)
     */
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

    /*
     * saltをIVに使用する想定の仮.
     * @param block
     * @param password
     * @param salt salt
     * @param c iteration count
     * @return 
     */
/*    public Block initAndSalt(Block block, byte[] password, byte[] salt, int c) {
        int[] nlen = block.getParamLength();
        nlen = new int[] {nlen[0]};
        int[] blen = new int[nlen.length];
        for (int i = 0; i < nlen.length; i++ ) {
            blen[i] = (nlen[i] + 7) / 8;
        }
        
        kdf.init(salt,c);
//        kdf.init(hmac);
        byte[][] dk = kdf.pbkdf(password, blen);
        
        block.init(dk[0], salt); // k, iv
        this.block = block;
        return block;
    }
*/    
    /**
     * 
     * @param block XXX-CBC
     * @param hmac PBKDF2用疑似乱数関数 MAC PRF
     * @param password password
     * @param salt salt
     * @param c iteration count
     * @return 
     */
    public Block init(Block block, MAC hmac, byte[] password, byte[] salt, int c) {
        kdf.init(hmac, salt, c);
        init(block, password);
        return block;
    }

    /**
     * PBES2params から生成したあとパスワードだけ
     * @param block
     * @param password 
     */
    public void init(Block block, byte[] password) {
        // hmac.init();
        this.block = block;
//        int[] nlen = block.getParamLength(); // ビット
//        int[] blen = new int[nlen.length]; // バイト
//        for ( int i = 0; i < nlen.length; i++ ) {
//            blen[i] = (nlen[i] + 7) / 8;
//        }
//        byte[][] dk = kdf.pbkdf(password, blen);
//        block.init(dk); // k, iv
        init(password);
    }
    
    /**
     * iv設定用(仮)
     * @param params iv
     */
    public void setParam(byte[]... params) {
        this.params = params;
    }

    /**
     * PBES2Paramからの生成想定.
     * @param password パスワード
     */
    public void init(byte[] password) {
        int[] ps = block.getParamLength();
        int[] bs = new int[ps.length];
        if ( params == null ) {
            params = new byte[0][];
        }
        int s = 0;
        for (int i = 0; i < ps.length - params.length; i++) {
            s += (ps[i] + 7) / 8;
        }
        byte[] ll = kdf.kdf(password, s);
        s = (ps[0] + 7) / 8;
        byte[] key = Arrays.copyOfRange(ll, 0, s);
        byte[][] prs = new byte[ps.length][];
        prs[0] = Arrays.copyOfRange(key, 0, s);
        if ( params.length >= 1) {
            prs[1] = params[0];
        } else {
            prs[1] = Arrays.copyOfRange(ll, s, s + (ps[1] + 7) / 8);
        }
        block.init(prs);
    }

    /**
     * メッセージ1つを暗号化する.
     * 
     * @param message 
     * @return ブロック長にpaddingされたメッセージの暗号
     */
    @Override
    public byte[] encrypt(byte[] message) {
        return block.doFinalEncrypt(message);
    }

    /**
     * 
     * @param message 暗号
     * @return 元メッセージ
     */
    @Override
    public byte[] decrypt(byte[] message) {
        return block.doFinalDecrypt(message);
    }

    void setBlock(Block encryptionScheme) {
        this.block = encryptionScheme;
    }
}
