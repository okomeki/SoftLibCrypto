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
package net.siisise.security.key;

import java.util.Arrays;
import net.siisise.security.mac.KMAC;

/**
 * NIST SP 800-108 4.4. KDF Using KMAC
 * とりあえず使えるだけ。他のものより安全ではない。
 */
public class KMACKDF implements KDF {

    final KMAC mac;

    public KMACKDF(KMAC mac) {
        this.mac = mac;
    }

    /**
     * KとLのみ指定する初期化.
     * @param K 鍵導出鍵 Kin, the key-derivation key.
     * @param L 出力ビット
     */
    public void init(byte[] K, long L) {
        init(K,L,"KDF");
    }
    
    /**
     * KとLのみ指定する初期化.
     * @param K 鍵導出鍵 Kin, the key-derivation key.
     * @param L 出力ビット
     * @deprecated 
     */
    @Deprecated
    public void init(byte[] K, int L) {
        init(K,L,"KDF");
    }

    /**
     *
     * @param K 鍵導出鍵
     * @param L output bit length
     * @param S KDF or KDF4X
     */
    public void init(byte[] K, long L, String S) {
        mac.init(K, L, S);
    }

    /**
     *
     * @param K 鍵導出鍵
     * @param L output bit length
     * @param S KDF or KDF4X
     * @deprecated 
     */
    @Deprecated
    public void init(byte[] K, int L, String S) {
        mac.init(K, L, S);
    }

    @Override
    public byte[] kdf(byte[] password) {
        return mac.doFinal(password);
    }

    @Override
    public byte[] kdf(byte[] password, int len) {
        mac.setMacLength(len);
        return Arrays.copyOf(kdf(password), len);
    }

}
