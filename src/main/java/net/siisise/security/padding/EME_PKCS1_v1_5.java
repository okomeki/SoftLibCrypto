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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * RFC 2313 PKCS #1 Version 1.5 Section 8. 暗号化プロセス
 * Section 8.1. 暗号化ブロックのフォーマット
 * EB = 00 || BT || PS || 00 || D.
 * 
 * BT の名称は廃止?
 * 00, 01 秘密鍵操作 (署名)
 * 02 公開鍵操作 (暗号化)
 * BT 00 PS は 00 または Paddingなし
 * BT 01 PS は FF
 * BT 02 PS は 疑似ランダム 00 以外
 * RFC 1423 と互換あり
 * 
 * @deprecated 脆弱
 */
@Deprecated
public class EME_PKCS1_v1_5 implements EME {
    
    SecureRandom rnd;
    
    public EME_PKCS1_v1_5() {
        try {
            rnd = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException ex) {
            // ない
        }
    }
    
    /**
     * PS は 8オクテット以上
     * @param k 鍵長
     * @return データ長 k - 11
     */
    @Override
    public int maxLength(int k) {
        return k - 11;
    }

    /**
     * RFC 8017 7.2.1.
     * @param k
     * @param M
     * @return EM
     */
    @Override
    public byte[] encoding(int k, byte[] M) {
        int mLen = M.length;
        if ( mLen > k - 11 ) {
            throw new SecurityException("message too long");
        }
        byte[] EM = new byte[k];
        EM[1] = 2;
        int p = k - mLen - 1;
        for ( int i = 2; i < p; i++ ) {
            EM[i] = (byte)(rnd.nextInt(255) + 1);
        }
        System.arraycopy(M, 0, EM, k - mLen, mLen);
        return EM;
    }

    @Override
    public void decodeCheck(int k, byte[] c) {
        if ( c.length != k ) {
            throw new SecurityException();
        }
    }

    @Override
    public byte[] decode(byte[] EM) {
        int i = 2;
        while (i < EM.length && EM[i] != 0) {
            i++;
        }
        
        if ( EM[0] != 0 || EM[1] != 2 || EM[i] != 0) {
            throw new SecurityException();
        }
        byte[] M = new byte[EM.length - i - 1];
        System.arraycopy(EM, i + 1, M, 0, M.length);
        return M;
    }
}
