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
package net.siisise.security.mac;

import net.siisise.io.Output;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.digest.SHA3Derived;
import net.siisise.security.digest.cSHAKE;
import net.siisise.security.key.KDF;

/**
 * Keccak MAC.
 * NIST SP 800-185
 * MACかXOF
 */
public abstract class KMAC extends Output.AbstractOutput implements MAC, KDF {
    private cSHAKE cshake;
    protected long L;

    // RFC 8702
    public static final OBJECTIDENTIFIER KmacWithSHAKE128 = new OBJECTIDENTIFIER("2.16.840.1.101.3.4.2.19");
    public static final OBJECTIDENTIFIER KmacWithSHAKE256 = new OBJECTIDENTIFIER("2.16.840.1.101.3.4.2.20");

    /**
     * 初期化要素.
     * @param c 暗号強度 128,256
     * @param key 鍵
     * @param length XOF出力サイズ bit
     * @param S オプションで設定可能な空文字列を含む可変長文字列. optional customization bit string of any length, including zero.
     */
    protected void init(int c, byte[] key, long length, String S) {
        L = length;
        cshake = new cSHAKE(c,length, "KMAC", S);
        byte[] newX = SHA3Derived.bytepad(SHA3Derived.encode_string(key), cshake.getBitBlockLength() / 8 );
        cshake.update(newX);
    }
    
    /**
     * 暗号強度はあらかじめ設定済みなので省けるかもしれず.
     * 
     * @param K 鍵
     * @param L 出力bitサイズ
     * @param S オプション可変長文字列
     */
    public abstract void init(byte[] K, long L, String S);
    @Deprecated
    public abstract void init(byte[] K, int L, String S);

    /**
     * KDFとして利用.
     * @param K 鍵導出鍵
     * @param L 出力ビットサイズ
     */
    public void initKDF(byte[] K, long L) {
        init(K, L, "KDF");
    }

    /**
     * KDF4Xとして利用.
     * @param K 鍵導出鍵
     * @param L 出力ビットサイズ
     */
    public void initKDF4X(byte[] K, long L) {
        init(K, L, "KDF4X");
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        cshake.update(src, offset, length);
    }

    @Override
    public byte[] sign() {
        cshake.update(SHA3Derived.right_encode(L));
        return cshake.digest();
    }

    @Override
    public int getMacLength() {
        return cshake.getDigestLength();
    }
    
    /**
     * 出力長の変更.
     * @param d バイト長
     */
    public void setMacLength(long d) {
        cshake.setBitDigestLength(d*8);
        L = d*8;
    }

    /**
     * 出力長をビット指定する.
     * 最後は下から埋め、上は0padding
     * @param d 出力ビット長
     */
    public void setMacBitLength(long d) {
        cshake.setBitDigestLength(d);
        L = d;
    }

    /**
     * 鍵長.
     * SHAKEの鍵長は任意なので適当に返す。
     * @return 
     */
    @Override
    public int getKeyLength() {
        return cshake.getBitBlockLength() / 8;
    }

    /**
     * KDF.
     * @param password
     * @return 
     */
    @Override
    public byte[] kdf(byte[] password) {
        update(password);
        return sign();
    }

    /**
     * 鍵導出 KDF.
     * KMACXOFは使えない.
     * @param password
     * @param len
     * @return 
     */
    @Override
    public byte[] kdf(byte[] password, int len) {
        setMacBitLength(len*8l);
//        L = 0; // でいいのか?
        update(password);
        return sign();
    }
}
