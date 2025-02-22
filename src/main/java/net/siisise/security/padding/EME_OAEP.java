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
import net.siisise.block.ReadableBlock;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.digest.SHA1;
import net.siisise.security.digest.XOF;

/**
 * EME の md と MGF1 の MessageDigest を別々に指定する必要あり?
 * 
 * RFC 8017 PKCS #1 7.1.1. では SHA-1, SHA-256, SHA-384, SHA-512 くらいが使える
 */
public class EME_OAEP implements EME {
    
    private SecureRandom rnd;
    private MGF mgf;
    MessageDigest md;
    byte[] lHash;
    int hLen;
//    long llen;
    
    /**
     * 再利用できるものであれば mgfmdとmd は同じインスタンス指定可能.
     * @param mgf MGF
     * @param md L用ハッシュ
     */
    public EME_OAEP(MGF mgf, MessageDigest md) {
        if ( md == null ) {
            md = new SHA1();
        }
        this.md = md;
        hLen = md.getDigestLength();
        // a.
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
     */
    public EME_OAEP(MessageDigest mgfMd, MessageDigest md) {
        this(new MGF1(mgfMd), md);
    }

    /**
     * MGF に SHAKE128 / SHAKE256 を使う場合
     * @param mgfXof MGF用 XOF
     * @param md L用
     */
    public EME_OAEP(XOF mgfXof, MessageDigest md) {
        this(new MGFXOF(mgfXof), md);
    }

    /**
     * encoding の開始前まで L を追加できる.
     * encoding後は固定して再利用する (初期化しない)
     * ToDo: 長さのチェックが必要だがチェックはしていない.
     * @param L ラベル
     */
    public void updateLabel(byte[] L) {
        md.update(L);
//        llen += L.length;
    }

    /**
     * 2.EME-OAEP encoding
     * MessageDigest と L はコンストラクタで指定する
     * 長さチェックは省略している.
     * @param k 出力長
     * @param m message
     * @return c cyphertext
     */
    @Override
    public byte[] encoding(int k, byte[] m) {
        // 2.a.
        if (lHash == null) { // Lを指定できるのは1回のみ
//            if ( llen >= (1l << 61)) { // SHA-1 どこで判定する?
//                throw new SecurityException("label too long");
//            }
            lHash = md.digest();
        }
        
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
        em.dwrite(seed); // maskedSeed
        em.dwrite(DB); // maskedDB
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
     * EME-OAEP 復号化操作.
     * 7.1.2. Decryption Operation
     *  3. EME-OAEP decoding.
     * @param EM パディングデータ
     * @return 元データ
     */
    @Override
    public byte[] decode(byte[] EM) {
        // a.
        if ( lHash == null ) {
            lHash = md.digest();
        }
        // b. 分離
        byte Y = EM[0];
        byte[] seed = Arrays.copyOfRange(EM, 1, 1 + hLen);
        byte[] DB = Arrays.copyOfRange(EM, 1 + hLen, EM.length);
        // c. seedMask = MGF(maskedDB, hLen)
        // d. seed = maskedSeed \\xor seedMask
        Bin.xorl(seed, mgf.generate(DB, hLen));
        // e. dbMask = MGF( seed, k - hLen - 1 )
        // f. DB = maskedDB \\xor dbMask
        Bin.xorl(DB, mgf.generate(seed, EM.length-hLen -1));
        // g.
        byte[] lHash2 = new byte[hLen];
//        System.arraycopy(DB, 0, lHash2, 0, hLen);
        ReadableBlock pac = ReadableBlock.wrap(DB);
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
