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
package net.siisise.security.mac;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.SecretKey;
import net.siisise.ietf.pkcs.asn1.AlgorithmIdentifier;
import net.siisise.iso.asn1.tag.NULL;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.digest.BlockMessageDigest;
import net.siisise.security.digest.SHA1;
import net.siisise.security.digest.SHA224;
import net.siisise.security.digest.SHA256;
import net.siisise.security.digest.SHA384;
import net.siisise.security.digest.SHA512;
import net.siisise.security.digest.SHA512224;
import net.siisise.security.digest.SHA512256;

/**
 * The Keyed-Hash Message Authentication Code (HMAC) FIPS 198-1.
 * Java標準ではない仮の鍵付きハッシュの形. あとで標準に寄せる。
 * ISO/IEC 10118 か ISO/IEC 9796
 * H 暗号ハッシュ関数.
 * K 秘密鍵 / 認証鍵.
 * B Hのブロックバイト長 512 / 8
 * L ハッシュバイト長 (MD5:128/8 SHA-1:160/8)
 * ipad 0x36をB回繰り返したもの
 * opad 0x5c をB回繰り返したもの
 * 
 * 鍵長 112ビット以上推奨/使用可
 *
 * 対応可能なアルゴリズム
 * HMAC-MD5         B  512bit L 128bit RFC 6151
 * HMAC-MD5-96      B  512bit L  96bit
 * HMAC-SHA-1       B  512bit L 160bit RFC 4634
 * HMAC-SHA-1-96    B  512bit L  96bit
 * HMAC-SHA-224     B  512bit L 224bit
 * HMAC-SHA-256     B  512bit L 256bit
 * HMAC-SHA-384     B 1024bit L 384bit
 * HMAC-SHA-512     B 1024bit L 512bit
 * HMAC-SHA-512/224 B 1024bit L 224bit
 * HMAC-SHA-512/256 B 1024bit L 256bit
 * HMAC-SHA3-224    B 1152bit L 224bit
 * HMAC-SHA3-256    B 1088bit L 256bit
 * HMAC-SHA3-384    B  832bit L 384bit
 * HMAC-SHA3-512    B  576bit L 512bit
 * RIPEMD-128/160   B  512bit
 * 
 * ハッシュ関数がPRFであればHMACもPRF MD5などはPRFではない
 *
 * FIPS PUB 198-1
 * FIPS 202 7 Conformance SHA-3のHMAC
 * RFC 2104 HMAC: Keyed-Hashing for Message Authentication.
 * RFC 2202 テスト
 * RFC 4231 Identifiers and Test Vector for HMAC-SHA-224, HMAC-SHA-256,
 *                          HMAC-SHA-384, and HMAC-SHA-512
 * RFC 6234 US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
 */
public class HMAC implements MAC {

    public static final OBJECTIDENTIFIER RSADSI = new OBJECTIDENTIFIER("1.2.840.113549");
    public static final OBJECTIDENTIFIER DIGESTALGORITHM = RSADSI.sub(2);
//    public static final String idHmacWithMD5 = DIGESTALGORITHM + ".6";
    public static final OBJECTIDENTIFIER idhmacWithSHA1 = DIGESTALGORITHM.sub(7);
    public static final OBJECTIDENTIFIER idhmacWithSHA224 = DIGESTALGORITHM.sub(8);
    public static final OBJECTIDENTIFIER idhmacWithSHA256 = DIGESTALGORITHM.sub(9);
    public static final OBJECTIDENTIFIER idhmacWithSHA384 = DIGESTALGORITHM.sub(10);
    public static final OBJECTIDENTIFIER idhmacWithSHA512 = DIGESTALGORITHM.sub(11);
    public static final OBJECTIDENTIFIER idhmacWithSHA512224 = DIGESTALGORITHM.sub(12);
    public static final OBJECTIDENTIFIER idhmacWithSHA512256 = DIGESTALGORITHM.sub(13);

//    private HMACSpi spi;
    private MessageDigest md;
    private int blockLength;
    private byte[] k_ipad;
    private byte[] k_opad;

    /**
     * 鍵をあとにする初期化.
     * ブロック長 512ビット または Spec対応用.
     * @param prf 擬似乱数関数
     */
    public HMAC(MessageDigest prf) {
        setPRF(prf);
    }
    
    /**
     * ブロック長 512ビット または Spec対応用.
     *
     * @param md MD5, SHA-1, SHA-256 など(汎用)512bitブロックのもの または
     * MessageDigestSpec対応版 擬似乱数関数
     * @param key 鍵 ブロック長 512bitのもの.
     */
    public HMAC(MessageDigest md, byte[] key) {
        setPRF(md);
        init(key);
    }

    /**
     * HMACの初期設定.
     * アルゴリズムが指定可能なのでkeyのみでdigestも指定可能.
     *
     * @param key アルゴリズムと鍵.
     */
    public HMAC(SecretKey key) {
        blockLength = 512;
        init(key);
    }

    /**
     * ブロック長 1024ビットなど用(仮).
     *
     * @param md SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA-3
     * @param blockBitLength
     * @param key
     */
    public HMAC(MessageDigest md, int blockBitLength, byte[] key) {
        this.md = md;
        blockLength = blockBitLength;
        init(key);
    }

    public HMAC(MessageDigest md, int blockBitLength, SecretKey key) {
        this.md = md;
        blockLength = blockBitLength;
        init(key);
    }

    /**
     * 鍵とアルゴリズムの指定.
     *
     * @param key
     */
    public final void init(SecretKey key) {
        String alg = key.getAlgorithm().toUpperCase();
        MessageDigest md = null;
        if (alg.startsWith("HMAC-")) { // RFC系の名前?
            md = (MessageDigest) BlockMessageDigest.getInstance(key.getAlgorithm().substring(5));
        } else if (alg.startsWith("HMAC")) {
            try {  // Java系の名前
                md = MessageDigest.getInstance(alg.substring(4));
            } catch (NoSuchAlgorithmException ex) {
                if (md == null) {
                    throw new SecurityException(ex);
                }
            }
        } else {
            throw new java.lang.UnsupportedOperationException();
        }

        setPRF(md);
        init(key.getEncoded());
    }
    
    /**
     * 擬似乱数関数.
     * BlockMessageDigest以外はブロック長 512bit 固定想定 MD5, SHA1, SHA-244, SHA-256 くらいなら使える.
     * @param md 正確なLとBがほしいのでBlockMessageDigest がいい
     */
    private void setPRF(MessageDigest md) {
        this.md = md;
        if ( md instanceof BlockMessageDigest) {
            blockLength = ((BlockMessageDigest)md).getBitBlockLength();
        } else {
            blockLength = 512;
        }
    }

    /**
     * HMACのバイト長.
     * @return バイト長
     */
    @Override
    public int getMacLength() {
        return md.getDigestLength();
    }

    /**
     * 鍵長(ブロック長バイト).
     * @return 
     */
    @Override
    public int getKeyLength() {
        return blockLength / 8;
    }

    /**
     * 鍵.
     * L以上の長さが必要.
     * B以上の場合はハッシュ値に置き換える.
     *
     * @param key 鍵
     */
    @Override
    public void init(byte[] key) {
        int b = blockLength / 8;
        md.reset();
        if (key.length > b) {
            key = md.digest(key);
        }

        k_ipad = new byte[b];
        k_opad = new byte[b];

        System.arraycopy(key, 0, k_ipad, 0, key.length);
        System.arraycopy(key, 0, k_opad, 0, key.length);

        for (int i = 0; i < b; i++) {
            k_ipad[i] ^= 0x36;
            k_opad[i] ^= 0x5c;
        }
        md.update(k_ipad);
    }

    @Override
    public void update(byte[] src) {
        md.update(src);
    }

    @Override
    public void update(byte[] src, int offset, int len) {
        md.update(src, offset, len);
    }

    @Override
    public byte[] sign() {
        byte[] m = md.digest();

        md.update(k_opad);
        byte[] r = md.digest(m);
        md.update(k_ipad);
        return r;
    }

    /**
     * RFC 8018 など.
     * @param ai OBJECTIDENTIFIERなど含む構造
     * @return HMAC
     */
    public static HMAC decode(AlgorithmIdentifier ai) {
        if ( ai.parameters != null && !(ai.parameters instanceof NULL)) {
            return null;
        }
        if ( ai.algorithm.equals(idhmacWithSHA1)) {
            return new HMAC(new SHA1());
        } else if ( ai.algorithm.equals(idhmacWithSHA224)) {
            return new HMAC(new SHA224());
        } else if (ai.algorithm.equals(idhmacWithSHA256)) {
            return new HMAC(new SHA256());
        } else if (ai.algorithm.equals(idhmacWithSHA384)) {
            return new HMAC(new SHA384());
        } else if (ai.algorithm.equals(idhmacWithSHA512)) {
            return new HMAC(new SHA512());
        } else if (ai.algorithm.equals(idhmacWithSHA512224)) {
            return new HMAC(new SHA512224());
        } else if (ai.algorithm.equals(idhmacWithSHA512256)) {
            return new HMAC(new SHA512256());
        }
        return null;
    }
}
