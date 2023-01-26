/*
 * Copyright 2023 Siisise Net.
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
package net.siisise.security.block;

/**
 * ブロック暗号
 */
public interface EncBlock {

    /**
     * block mode 暗号化用.
     *
     * @param src ソースデータ列
     * @param offset src offset
     * @param length 固定サイズの倍数であること. バイト長.
     * @return 暗号化データxn
     */
    byte[] encrypt(byte[] src, int offset, int length);
    /**
     * ワード単位で処理すれば速いかなと思ったがバイト列から変換が入るとあまり変わらず
     * CBCなど前処理とあわせると強い
     * @param src 32bit単位のソースデータ列.
     * @param offset src offset
     * @param length src length 長さ 固定サイズの倍になっていること
     * @return 暗号化データブロックxn
     */
    int[] encrypt(int[] src, int offset, int length);
    long[] encrypt(long[] src, int offset, int length);

    void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length);

    /**
     * encrypy(src, 0, src.length) へリダイレクト
     * 
     * @param src
     * @return 
     */
    byte[] encrypt(byte[] src);
    int[] encrypt(int[] src);
    long[] encrypt(long[] src);

    /**
     * 1ブロック暗号化処理.
     * 固定長のブロック単位で呼び出される。
     * パディングは考慮しない。
     *
     * @param src ブロックを含んだ列
     * @param offset ブロックの位置
     * @return 暗号化された列
     */
    byte[] encrypt(byte[] src, int offset);
    int[] encrypt(int[] src, int offset);
    long[] encrypt(long[] src, int offset);
}
