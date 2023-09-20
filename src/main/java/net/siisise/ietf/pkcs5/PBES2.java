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
import net.siisise.io.FileIO;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.block.Block;
import net.siisise.security.mac.MAC;

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
        
    }

    /**
     * メッセージ1つを暗号化する.
     * 
     * @param message 
     * @return ブロック長にpaddingされたメッセージの暗号
     */
    @Override
    public byte[] encrypt(byte[] message) {
        int blength = block.getBlockLength();
        
        int padlength = blength - (message.length % blength);
        byte[] src = new byte[message.length + padlength];
        System.arraycopy(message, 0, src, 0, message.length);
        Arrays.fill(src, message.length, src.length, (byte)padlength);
        return block.encrypt(src, 0, src.length);
    }

    /**
     * 
     * @param message 暗号
     * @return 元メッセージ
     */
    @Override
    public byte[] decrypt(byte[] message) {
        byte[] mpad = block.decrypt(message, 0, message.length);
        FileIO.dump(mpad); // DEBUG中
        byte[] d = new byte[mpad.length - mpad[mpad.length - 1]];
        System.arraycopy(mpad, 0, d, 0, d.length);
        return d;
    }

    void setBlock(Block encryptionScheme) {
        this.block = encryptionScheme;
    }
}
