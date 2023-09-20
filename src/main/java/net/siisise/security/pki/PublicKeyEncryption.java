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
package net.siisise.security.pki;

/**
 * 公開鍵暗号的なもの.
 * key でいい気がする.
 * 暗号化、復号、署名、検証がひつよう
 */
public interface PublicKeyEncryption {
    
    /**
     * 鍵など設定する.
     * @param param 
     */
    void init(byte[]... param);
    
    /**
     * 暗号化可能な最大サイズっぽいもの.
     * マイナスなら制限なしくらい.
     * @return 
     */
    long maxLength();
    
    byte[] encode(byte[] src);
    byte[] decode(byte[] encd);

    byte[] sign(byte[] src);
    byte[] verify(byte[] src, byte[] sign);
    
}
