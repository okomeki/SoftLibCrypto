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
package net.siisise.security.padding;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;

/**
 * EME の md と MGF1 の MessageDigest を別々に指定する必要あり?
 * 
 * RFC 8017 PKCS #1 7.1.1. では SHA-1, SHA-256, SHA-384, SHA-512 くらいが使える
 */
public class EME_OAEP implements EME {
    
    private SecureRandom rnd;
    private MGF mgf;
    
    byte[] lHash;
    int hLen;
    
    /**
     * 再利用できるものであれば mgfmdとmd は同じインスタンス指定可能.
     * @param mgf MGF
     * @param md L用ハッシュ
     * @param L ラベル
     */
    public EME_OAEP(MGF mgf, MessageDigest md, byte[] L) {
        lHash = md.digest(L == null ? new byte[0] : L);
        hLen = lHash.length;
        this.mgf = mgf;
        try {
            rnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            // ない
        }
    }

    /**
     * 
     * @param mgfMd MGF用 hash
     * @param md L用 hash
     * @param L 
     */
    public EME_OAEP(MessageDigest mgfMd, MessageDigest md, byte[] L) {
        this(new MGF1(mgfMd), md, L );
    }
    
    /**
     * 2.EME-OAEP encoding
     * MessageDigest と L はコンストラクタで指定する
     * 長さチェックは省略している.
     * @param k
     * @param m message
     * @return c cyphertext
     */
    @Override
    public byte[] encoding(int k, byte[] m) {
        int mLen = m.length;
        // 1. 長さチェック a. Lの長さ長すぎるので省略
        // b.
        if ( mLen > k - 2*hLen - 2) {
            throw new SecurityException("message too long");
        }
        
        byte[] DB = new byte[k-hLen-1];
        System.arraycopy(lHash, 0, DB, 0, hLen);
        DB[DB.length - mLen - 1] = 1;
        System.arraycopy(m, 0, DB, DB.length - mLen, mLen);
        // d.
        byte[] seed = new byte[hLen];
        rnd.nextBytes(seed);
        // e. generate
        // f. XOR
        mgf.xorl(DB, seed); // maskedDB
        // g. generate
        // h. XOR
        mgf.xorl(seed,DB); // maskedSeed
        // i.
        Packet em = new PacketA();
        em.write(0x00);
        em.write(seed); // maskedSeed
        em.write(DB); // maskedDB
        return em.toByteArray();
    }

    @Override
    public int maxLength(int k) {
        return k - 2*hLen - 2; 
    }
    
    @Override
    public void decodeCheck(int k, byte[] C) {
        // 1. 長さチェック a. 長すぎるので省略
        // b. cLen != k
        // c. k < 2hLen + 2
        if ( C.length != k || k < 2 * hLen + 2 ) {
            throw new SecurityException();
        }
    }
    
    /**
     * EME-OAEPデコード
     * @param EM パディングデータ
     * @return 元データ
     */
    @Override
    public byte[] decode(byte[] EM) {
        // a. 計算済み
        // b. 分離
        byte Y = EM[0];
        //byte[] maskedSeed = new byte[hLen];
        byte[] maskedSeed = Arrays.copyOfRange(EM, 1, 1 + hLen);
        //System.arraycopy(EM, 1, maskedSeed, 0, hLen);
//        byte[] maskedDB = new byte[EM.length - hLen - 1];
        byte[] maskedDB = Arrays.copyOfRange(EM, 1 + hLen, EM.length);
//        System.arraycopy(EM, hLen + 1, maskedDB, 0, maskedDB.length);
        // c.
        // d.
        byte[] seed = Bin.xorl(maskedSeed, mgf.generate(maskedDB, hLen));
        // e.
        // int k = EM.length;
        // f.
        byte[] DB = Bin.xorl(maskedDB, mgf.generate(seed, EM.length-hLen -1));
        // g.
        byte[] lHash2 = new byte[hLen];
//        System.arraycopy(DB, 0, lHash2, 0, hLen);
        PacketA pac = new PacketA(DB);
        pac.read(lHash2);
        // PS
        int i;
        do {
            i = pac.read();
        } while ( i == 0 );
        if ( !Arrays.equals(lHash, lHash2) || Y != 0 || i != 1) {
            throw new SecurityException("decryption error");
        }
        return pac.toByteArray();
    }
}
