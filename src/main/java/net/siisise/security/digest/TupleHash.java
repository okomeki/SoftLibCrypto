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
 * TupleHash.
 * update X 1回で1つ分のデータということにしておく.
 * update1回ごとに長さを付加する.
 */
public class TupleHash extends cSHAKE {
    private final long L;

    /**
     * TupleHash. 出力サイズと文字列指定.
     * @param c 暗号強度 128 or 256
     * @param L 出力サイズ bit
     * @param S オプションで設定可能な空文字列を含む可変長文字列. optional customization bit string of any length, including zero.
     */
    protected TupleHash(int c, int L, String S) {
        super(c, L, "TupleHash", S);
        this.L = L;
    }

    /**
     * XOF用.
     * @param c 暗号強度 128 or 256
     * @param L 出力サイズ bit
     * @param Ltag 0の予定
     * @param S オプションで設定可能な空文字列を含む可変長文字列. optional customization bit string of any length, including zero.
     */
    protected TupleHash(int c, int L, int Ltag, String S) {
        super(c, L, "TupleHash", S);
        this.L = Ltag;
    }

    /**
     * まとめただけ
     * @param src X
     */
    public void update(byte[][] src) {
        for (byte[] s : src) {
            update(s, 0, s.length);
        }
    }

    /**
     * 一回分.
     * @param src ソース
     * @param offset 位置
     * @param length 長さ
     */
    @Override
    public void engineUpdate(byte[] src, int offset, int length) {
        // SHA3Derived.encode_stringの分解
        byte[] l = SHA3Derived.left_encode(length * 8l);
        super.engineUpdate(l,0,l.length);
        super.engineUpdate(src, offset, length);
    }

    @Override
    protected byte[] engineDigest() {
        byte[] encLen = SHA3Derived.right_encode(L);
        super.engineUpdate(encLen,0,encLen.length);
        return super.engineDigest();
    }
}
