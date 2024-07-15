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

import java.security.MessageDigest;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.block.Block;
import net.siisise.security.block.DES;
import net.siisise.security.block.RC2;
import net.siisise.security.digest.MD2;
import net.siisise.security.digest.MD5;
import net.siisise.security.digest.SHA1;
import net.siisise.security.mode.CBC;
import net.siisise.security.mode.PKCS7Padding;

/**
 * RFC 8018 6. Encryption Schemes
 * パスワードからIVと暗号鍵を生成して暗号化する方式.
 * 費用順的なPADDINGと同じなので暗号の方に
 * @deprecated DES,RC2などを使用するため旧式
 */
@Deprecated
public class PBES1 implements PBES {
    
    static final OBJECTIDENTIFIER pbeWithMD2AndDES_CBC = PBKDF2.PKCS5.sub(1);
    static final OBJECTIDENTIFIER pbeWithMD5AndDES_CBC = PBKDF2.PKCS5.sub(3);
    static final OBJECTIDENTIFIER pbeWithMD2AndRC2_CBC = PBKDF2.PKCS5.sub(4);
    static final OBJECTIDENTIFIER pbeWithMD5AndRC2_CBC = PBKDF2.PKCS5.sub(6);
    static final OBJECTIDENTIFIER pbeWithSHA1AndDES_CBC = PBKDF2.PKCS5.sub(10);
    static final OBJECTIDENTIFIER pbeWithSHA1AndRC2_CBC = PBKDF2.PKCS5.sub(11);
    // PBKDF2 12 
    // PBES2 13 

    private Block block;
    private byte[] k;
    private byte[] iv;
    
    /**
     *
     * A.3.
     * pbeWithMD2AndDES
     * pbeWithMD2AndRC2
     * pbeWithMD5AndDES
     * pbeWithMD5AndRC2
     * pbeWithSHA1AndDES
     * pbeWithSHA1AndRC2
     * @param block DES/CBC RC2/CBC
     * @param digest PBKDFのパラメータ
     * @param password PBKDFのパラメータ
     * @param salt PBKDFのパラメータ
     * @param c ハッシュ繰り返し数 PBKDFのパラメータ
     */
    public void init(Block block, MessageDigest digest, byte[] password, byte[] salt, int c) {
        this.block = block;
        byte[] dk = PBKDF1.pbkdf1(digest, password, salt, c, 16);
        k = new byte[8];
        iv = new byte[8];
        System.arraycopy(dk, 0, k, 0, 8);
        System.arraycopy(dk, 8, iv, 0, 8);
        block.init(k,iv);
    }

    public void init(OBJECTIDENTIFIER oid, byte[] password, byte[] salt, int c) {
        MessageDigest md;
        Block b;
        if ( pbeWithMD2AndDES_CBC.equals(oid)) {
            md = new MD2();
            b = new DES();
        } else if ( pbeWithMD2AndRC2_CBC.equals(oid)) {
            md = new MD2();
            b = new RC2();
        } else if ( pbeWithMD5AndDES_CBC.equals(oid)) {
            md = new MD5();
            b = new DES();
        } else if ( pbeWithMD5AndRC2_CBC.equals(oid)) {
            md = new MD5();
            b = new RC2();
        } else if ( pbeWithSHA1AndDES_CBC.equals(oid)) {
            md = new SHA1();
            b = new DES();
        } else if ( pbeWithSHA1AndRC2_CBC.equals(oid)) {
            md = new SHA1();
            b = new RC2();
        } else {
            throw new SecurityException();
        }
        init(new CBC(b), md, password, salt, c);
    }

    /** 2回目があれば */
    public void init() {
        block.init(k,iv);
    }
    
    /**
     * 基本1回のみ。2回目以降初期化せずに使えるかもしれない
     * 毎回padding付き
     * @param message M メッセージ
     * @return C = encrypt(EM)
     */
    @Override
    public byte[] encrypt(byte[] message) {
        // RFC 1423 PEM と PKCS の padding は同じ
        PKCS7Padding pad = new PKCS7Padding(block);
        return pad.doFinalEncrypt(message);
    }
    
    /**
     * 64bit系 DES CBC または RC2 CBC
     * 
     * @param block DES CBC または RC2 CBC
     * @param digest MD2, MD5, SHA-1
     * @param message メッセージ
     * @param password パスワード
     * @param salt 8オクテット
     * @param c 繰り返し 1000ぐらい
     * @return 
     */
    public static byte[] encrypt(Block block, MessageDigest digest, byte[] message, byte[] password, byte[] salt, int c) {
        PBES1 pb = new PBES1();
        pb.init(block, digest, password, salt, c);
        return pb.encrypt(message);
    }
    
    /**
     *
     * @param message padding されているもの
     * @return デコードされたもの
     */
    @Override
    public byte[] decrypt(byte[] message) {
        PKCS7Padding enc = new PKCS7Padding(block);
        return enc.doFinalDecrypt(message);
    }
    
    /**
     *
     * @param block DES CBC または RC2 CBC
     * @param digest MD2, MD5 または SHA-1
     * @param message
     * @param password
     * @param salt
     * @param c
     * @return
     */
    public static byte[] decrypt(Block block, MessageDigest digest, byte[] message, byte[] password, byte[] salt, int c) {
        PBES1 pb = new PBES1();
        pb.init(block, digest, password, salt, c);
        return pb.decrypt(message);
    }
    
}
