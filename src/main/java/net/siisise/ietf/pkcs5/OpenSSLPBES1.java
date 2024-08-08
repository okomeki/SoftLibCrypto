/*
 * Copyright 2024 okome.
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
import net.siisise.security.block.AES;
import net.siisise.security.block.Block;
import net.siisise.security.block.DES;
import net.siisise.security.block.RC2;
import net.siisise.security.block.TripleDES;
import net.siisise.security.digest.MD5;
import net.siisise.security.mode.CBC;
import net.siisise.security.mode.CFB;
import net.siisise.security.mode.CTR;
import net.siisise.security.mode.ECB;
import net.siisise.security.mode.GCM;
import net.siisise.security.mode.OFB;
import net.siisise.security.mode.PKCS7Padding;

/**
 * PBKDF1のOpenSSL拡張とAESアルゴリズム対応のPBES1.
 * PBKDFは鍵の生成のみに利用する。
 * IVはsaltと兼用で指定する saltはIVの先頭64bit, IVは128bitなど
 * 
 */
public class OpenSSLPBES1 extends PBES1 {
    
    public OpenSSLPBES1() {
        super(new OpenSSLPBKDF1());
    }

    /**
     * 
     * @param salt saltとiv兼用
     * @param c 
     */
    @Override
    public void init(byte[] salt, int c) {
        iv = salt;
        kdf.init(salt, c);
    }
    
    /**
     * 
     * @param block
     * @param digest PBKDF1 パラメータ
     * @param password
     */
    @Override
    public void init(Block block, MessageDigest digest, byte[] password) {
        this.block = block;
        kdf.init(digest);
        int[] dkLens = block.getParamLength();
        byte[] dk = kdf.kdf(password, (dkLens[0]+7)/8);
        k = dk;
//        iv = kdf.salt;
        block.init(k,iv);
    }

    /**
     * 
     * @param alg DEK-Infoのアルゴリズム
     * @param password 
     */
    public void init(String alg, byte[] password) {
        Block b;
        String[] algp = alg.split("-");
        int off = 1;
        if ("AES".equals(algp[0])) {
            if ("128".equals(algp[1])) {
                b = new AES(128);
            } else if ("192".equals(algp[1])) {
                b = new AES(192);
            } else if ("256".equals(algp[1])) {
                b = new AES(256);
            } else {
                throw new java.lang.UnsupportedOperationException(alg);
            }
            off = 2;
        } else if ("DES".equals(algp[0])) {
            if ("EDE3".equals(algp[1])) {
                b = new TripleDES();
                off = 2;
            } else {
                b = new DES();
                off = 1;
            }
        } else if ("RC2".equals(algp[0])) {
            b = new RC2();
            off = 1;
        } else {
            throw new UnsupportedOperationException(alg);
        }
        if ("CBC".equals(algp[off])) {
            b = new PKCS7Padding(new CBC(b));
        } else if ("ECB".equals(algp[off])){
            b = new PKCS7Padding(new ECB(b));
        } else if ("CFB".equals(algp[off])){
            b = new PKCS7Padding(new CFB(b));
        } else if ("OFB".equals(algp[off])){
            b = new PKCS7Padding(new OFB(b));
        } else if ("CTR".equals(algp[off])){
            b = new CTR(b);
        } else if ("GCM".equals(algp[off])){
            b = new GCM(b);
        } else {
            throw new UnsupportedOperationException(alg);
        }
        
        init(b, new MD5(), password);
    }

    public void init(String alg, byte[] password, byte[] salt) {
        init(salt, 1); // PBKDFの初期化
        init(alg, password);
    }
    
}
