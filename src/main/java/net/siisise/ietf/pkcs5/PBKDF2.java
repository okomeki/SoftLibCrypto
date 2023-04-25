/*
 * Copyright 2022 Siisise Net.
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

import java.io.IOException;
import net.siisise.io.PacketA;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.iso.asn1.tag.SEQUENCE;
import net.siisise.security.digest.SHA1;
import net.siisise.security.mac.HMAC;
import net.siisise.security.mac.MAC;

/**
 * KDF
 * RFC 2898
 * RFC 8018 PKCS #5 v2.1
 */
public class PBKDF2 implements PBKDF {

    public static final OBJECTIDENTIFIER PKCS = new OBJECTIDENTIFIER("1.2.840.113549.1"); // pkcs
    public static final OBJECTIDENTIFIER PKCS5 = PKCS.sub(5); // pkcs-5
    public static final OBJECTIDENTIFIER OID = PKCS5.sub(12); // id-PBKDF2
    
    private MAC prf;
    byte[] salt;
    int c;
    
    /**
     * デフォルトはSHA-1
     * @deprecated SHA-1 は廃止
     */
    public PBKDF2() {
        prf = new HMAC(new SHA1()); // デフォルト 非推奨?
    }
    
    /**
     * HMAC-SHA-1 など HMAC-いろいろ.
     * RFC 8018 B.1. では
     * SHA-1, SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/224, SHA-512/256 などを想定 
     * @param m HMAC-SHA-xx
     */
    public PBKDF2(MAC m) {
        prf = m;
    }
    
    /**
     * 
     * @param prf 使用するHMACアルゴリズム
     */
    public void init(MAC prf) {
        this.prf = prf;
    }
    
    public void init(MAC prf, byte[] salt, int c) {
        this.prf = prf;
        this.salt = salt;
        this.c = c;
    }
    
    public void init(byte[] salt, int c) {
        this.salt = salt;
        this.c = c;
    }
    
    /**
     * salt と c かな?
     * @deprecated まだない
     * @param params
     * @throws IOException 
     */
    public void setASN1Params(byte[] params) throws IOException {
        SEQUENCE ps = (SEQUENCE) ASN1Util.toASN1(params);
        
    }
    
    /**
     * 
     * @param password HMAC パスワード
     * @param salt ソルト
     * @param c 繰り返す数 1000以上ぐらい
     * @param dkLen 戻り値の長さ
     * @return 
     */
    @Override
    public byte[] pbkdf(byte[] password, byte[] salt, int c, int dkLen) {
        return pbkdf2(prf, password, salt, c, dkLen);
    }
    
    @Override
    public byte[] pbkdf(byte[] password, int dkLen) {
        return pbkdf2(prf, password, salt, c, dkLen);
    }
    
    public byte[][] pbkdf(byte[] password, int... dkLens) {
        int sum = 0;
        for ( int i = 0; i < dkLens.length; i++) {
            sum += dkLens[i];
        }
        
        byte[] dkbase = pbkdf(password, sum);
        int offset = 0;
        byte[][] dks = new byte[dkLens.length][];
        for (int i = 0; i < dkLens.length; i++ ) {
            dks[i] = new byte[dkLens[i]];
            System.arraycopy(dkbase,offset,dks[i],0,dkLens[i]);
            offset += dkLens[i];
        }
        return dks;
    }
    
    /**
     * PBKDF2 本体.
     * HMAC以外も使えるようにしてある
     * @param prf HMACアルゴリズム
     * @param password HMAC用パスワード
     * @param salt ソルト
     * @param c 繰り返す数
     * @param dkLen 戻り長さ (バイト)
     * @return 
     */
    public static byte[] pbkdf2(MAC prf, byte[] password, byte[] salt, int c, int dkLen) {
        int hLen = prf.getMacLength();
        // 1.
        if ( dkLen > 0xffffffffl * hLen ) { // Javaの配列長の範囲外
            throw new IllegalStateException("derived key too long");
        }
        prf.init(password);
        int l = (int)(((long)dkLen + hLen - 1) / hLen); // dkLenに必要なブロック数
//        int r = dkLen % hLen;
        PacketA pac = new PacketA();
        for (int i = 1; i <= l; i++) {
            pac.dwrite(f(prf, salt, c, i));
        }
        byte[] dk = new byte[dkLen];
        pac.read(dk);
        return dk;
    }

    /**
     * パスワードはHMACで保持できるので省略した
     * @param prf HMAC アルゴリズム パスワード設定済み
     * @param salt ソルト
     * @param c ループ回数
     * @param i カウント
     * @return 1回分
     */
    private static byte[] f(MAC prf, byte[] salt, int c, int i) {
        prf.update(salt);
        byte[] key = new byte[4];
        key[0] = (byte)(i >>> 24);
        key[1] = (byte)((i >> 16) & 0xff);
        key[2] = (byte)((i >> 8) & 0xff);
        key[3] = (byte)(i  & 0xff);
        byte[] u = prf.doFinal(key);
        byte[] f = u;
        int len = u.length;
        for (int j = 1; j < c; j++ ) {
            u = prf.doFinal(u);
            for ( int k = 0; k < len; k++) {
                f[k] ^= u[k];
            }
        }
        return f;
    }
}
