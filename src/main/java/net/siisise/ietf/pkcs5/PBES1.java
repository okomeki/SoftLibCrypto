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
    
    final PBKDF1 kdf;

    protected Block block;
    protected byte[] k;
    protected byte[] iv;
    
    public PBES1() {
        kdf = new PBKDF1();
    }
    
    protected PBES1(PBKDF1 kdf) {
        this.kdf = kdf;
    }

    /**
     * PBEParameter
     * @param salt PBKDFのパラメータ 8バイト(64bit)以上推奨
     * @param c ハッシュ繰り返し数 PBKDFのパラメータ 1000以上推奨
     */
    public void init(byte[] salt, int c) {
        kdf.init(salt, c);
    }
    
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
     */
    public void init(Block block, MessageDigest digest, byte[] password) {
        this.block = block;
        kdf.init(digest);
        byte[] dk = kdf.kdf(password, 16);
        k = new byte[8];
        iv = new byte[8];
        System.arraycopy(dk, 0, k, 0, 8);
        System.arraycopy(dk, 8, iv, 0, 8);
        block.init(k,iv);
    }
    
    public void init(Block block, MessageDigest digest, byte[] password, byte[] salt, int c) {
        init(salt, c);
        init(block, digest, password);
    }

    public void init(OBJECTIDENTIFIER oid, byte[] password) {
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
        init(new PKCS7Padding(new CBC(b)), md, password);
    }

    /** 2回目があれば */
    public void init() {
        block.init(k,iv);
    }
    
    @Override
    public int getBlockLength() {
        return block.getBlockLength();
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
        return block.doFinalEncrypt(message);
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
        pb.init(salt, c);
        pb.init(block, digest, password);
        return pb.encrypt(message);
    }
    
    /**
     *
     * @param message padding されているもの
     * @return デコードされたもの
     */
    @Override
    public byte[] decrypt(byte[] message) {
        return block.doFinalDecrypt(message);
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
        pb.init(salt, c);
        pb.init(block, digest, password);
        return pb.decrypt(message);
    }
    
}
