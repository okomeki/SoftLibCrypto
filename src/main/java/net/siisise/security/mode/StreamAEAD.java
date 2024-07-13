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
package net.siisise.security.mode;

import net.siisise.security.stream.Stream;

/**
 * 認証付き暗号.
 * 暗号化しないAADと暗号化する本文を認証できる方式。
 * tag() または doFinalEncrypt() でタグを確認できる。
 * doFinalDecrypt() も検証に利用可能かもしれない。
 *
 * init で AAD を追加できる形式。
 * update で追加する方法も要検討。
 * tag() 単体または doFinalEncrypt でタグ出力が得られたりする。 
 * doFinalDecrypt では末尾についているタグを検証する。
 * doFinalDecrypt() パラメータなしまたはtagサイズに不足する場合は必ず失敗する?
 *
 * TLS 1.2
 */
public interface StreamAEAD extends Stream {

    /**
     * パラメータ受け渡し
     * @param params key, iv, aad の3つで受け付ける
     */
    void init(byte[]... params);
    
    /**
     * MAC.
     *
     * @return MAC
     */
    byte[] tag();

    default byte[] doFinalEncrypt() {
        return doFinalEncrypt(new byte[0]);
    }

    default byte[] doFinalEncrypt(byte[] src) {
        return doFinalEncrypt(src, 0, src.length);
    }

    byte[] doFinalEncrypt(byte[] src, int offset, int length);

    default byte[] doFinalDecrypt() {
        return doFinalDecrypt(new byte[0]);
    }

    default byte[] doFinalDecrypt(byte[] src) {
        return doFinalDecrypt(src, 0, src.length);
    }

    byte[] doFinalDecrypt(byte[] src, int offset, int length);
}
