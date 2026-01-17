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
package net.siisise.security.digest;

/**
 * ParallelHash 256bit
 */
public class ParallelHash256 extends ParallelHash {

    /**
     * ParallelHash
     *
     * @param b block size in bytes
     * @param L hash bit length ハッシュ出力bit長
     * @param S customization bit string 付加文字
     */
    public ParallelHash256(int b, int L, String S) {
        super(256, b, L, false, S);
    }

    /**
     * ParallelHash
     *
     * @param b block size in bytes
     * @param L hash bit length ハッシュ出力bit長
     * @param xof XOF有効/無効
     * @param S customization bit string 付加文字
     */
    ParallelHash256(int b, int L, boolean xof, String S) {
        super(256, b, L, xof, S);
    }
}
