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
package net.siisise.security.sign;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.siisise.lang.Bin;
import net.siisise.security.padding.MGF;

/**
 * Section 8.1.
 * EMSA4 のオクテット文字列版らしい
 */
public class EMSA_PSS implements EMSA {

    final MessageDigest md;
    long len;
    final MGF mgf;
    final int sLen;

    SecureRandom rnd;

    /**
     * 9.1.1 Encoding Operation のOptionsパラメータを受ける
     * @param hash hash function (hLen denotes the length in octets of the hash function output)
     * @param mgf generate mask generation function
     * @param sLen intnded length in octets of the salt
     */
    public EMSA_PSS(MessageDigest hash, MGF mgf, int sLen) {
        this.md = hash;
        this.mgf = mgf;
        this.sLen = sLen;
        try {
            rnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(EMSA_PSS.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public void update(byte[] M) {
        md.update(M);
        len += M.length;
    }

    @Override
    public void update(byte[] M, int offset, int length) {
        md.update(M, offset, length);
        len += length;
    }

    @Override
    public void update(ByteBuffer buffer) {
        len += buffer.limit() - buffer.position();
        md.update(buffer);
    }

    @Override
    public long size() {
        return len;
    }

    /**
     * Section 9.1.1 の Input を受ける
     * M message to be encoded, an octet string
     * @param emBits emBits maximal bit length of the integer OS2IP (EM), at least 8hLen + 8sLen + 9
     *  OS2IP(EM)の最大出力ビット長 8hLen + 8sLen + 9
     * @return EM encoded message, an octet string of length emLen = \ ceil(emBits/8)
     */
    @Override
    public byte[] encode(int emBits) {
        byte[] mHash = md.digest();
        len = 0; // 判定はまだしていない
        //int emBit2 = (mHash.length + sLen) * 8 + 9;
        int emLen = (emBits + 7) / 8;
        // 3.
        if ( emLen < mHash.length + sLen + 2 ) {
            throw new SecurityException("encoding error");
        }
        // 4.
        byte[] salt = new byte[sLen];
        rnd.nextBytes(salt);
        // 5. 6.
        md.update(new byte[8]); // Padding1
        md.update(mHash);
        byte[] H = md.digest(salt);
        // 7.
        int psLen = emLen - sLen - H.length - 2;
//        byte[] PS = new byte[emLen - sLen - H.length - 2];
        // 8.
        byte[] DB = new byte[psLen + 1 + salt.length];
        DB[psLen] = 0x01;
        System.arraycopy(salt, 0, DB, psLen + 1, sLen);
        // 9. 10.
        Bin.xorl(DB, mgf.generate(H, emLen - H.length - 1));
        // 11.
        DB[0] &= 0xff >> (8*emLen - emBits);
        // 12.
        byte[] EM = new byte[DB.length + H.length + 1];
        System.arraycopy(DB, 0, EM, 0, DB.length);
        System.arraycopy(H, 0, EM, DB.length, H.length);
        EM[DB.length + H.length] = (byte)0xbc;
        return EM;
    }

    /**
     * 9.1.2. Verification Operation
     * M message to be verified, an octet string 事前にupdateで渡しても可
     * @param EM encoded message, an octet string of length emLen = \ ceil(emBits/8) emBits maxinal bit length of the integer OS2IP(EM), at least 8hLen + 9sLen + 9
     * @param emBits
     * @return true: consistent false: inconsistent
     */
    @Override
    public boolean verify(byte[] EM, int emBits) {
        // 1. 省略
        byte[] mHash = md.digest();
        int emLen = (emBits + 7) / 8;
        len = 0; // 判定はまだしていない
        // 3.
        if ( emLen < mHash.length + sLen + 2 ) {
            return false;
        }
        if (EM[EM.length-1] != (byte)0xbc) {
            return false;
        }
        
        byte[] maskedDB = new byte[emLen - mHash.length - 1];
        System.arraycopy(EM, 0, maskedDB, 0, maskedDB.length);
        byte[] H = new byte[mHash.length];
        System.arraycopy(EM, maskedDB.length, H, 0, H.length);
        // 6.
        int ll = (8*emLen - emBits);
        if ( (EM[0] & 0xff & ((0xff << (8-ll)))) != 0) {
            return false;
        }
        // 7.
        byte[] DB = mgf.generate(H, emLen - H.length - 1);
        // 8.
        Bin.xorl(DB, maskedDB);
        // 9.
        DB[0] &= 0xff >> ll;
        // 10.
        ll = emLen - H.length - sLen - 2;
        for ( int i = 0; i < ll; i++ ) {
            if ( DB[i] != 0) {
                return false;
            }
        }
        // ?
        if ( DB[emLen - H.length -sLen - 2] != 0x01 ) {
            return false;
        }
        byte[] Md = new byte[8+ mHash.length + sLen];
        System.arraycopy(mHash, 0, Md, 8, mHash.length);
        System.arraycopy(DB, DB.length - sLen, Md, 8 + mHash.length, sLen);
        byte[] Hd = md.digest(Md);
        return Arrays.equals(H, Hd);
    }
    
}
