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
package net.siisise.security.digest;

/**
 * update 1つをX1つとする
 */
public class TupleHash128 extends cSHAKE128 {
    int L;

    public TupleHash128(int L, String S) {
        super(L, "TupleHash", S);
        this.L = L;
    }

    public void update(byte[][] src) {
        for (byte[] s : src) {
            updateTuple(s, 0, s.length);
        }
    }

    public void updateTuple(byte[] src, int offset, int length) {
        update(SHA3Derived.encode_string(src, offset, length).toByteArray());
    }
    
    @Override
    protected byte[] engineDigest() {
        update(SHA3Derived.right_encode(L));
        return super.engineDigest();
    }
}
