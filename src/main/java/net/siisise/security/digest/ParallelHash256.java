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
 *
 */
public class ParallelHash256 extends ParallelHash {

    /**
     * 
     * @param b block byte size
     * @param l hash bit length ハッシュ出力bit長
     * @param S 付加文字
     */
    public ParallelHash256(int b, int l, String S) {
        super(256, b, l, S);
    }
    
}
