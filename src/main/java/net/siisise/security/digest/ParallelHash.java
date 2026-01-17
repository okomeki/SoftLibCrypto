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
 * NIST SP 800-185 6 ParallelHash. 並列ではないかも.
 */
public class ParallelHash extends RawcSHAKE {

    /**
     * block size in bytes. 並列ハッシュのブロックサイズ
     */
    final int B;
    /**
     * XOFは0にする
     */
    protected int L;
    /**
     * block 残サイズ
     */
    int size;
    private final SHAKE shake;
    int n;

    /**
     *
     * @param c 暗号強度 128 または 256
     * @param B block size in bytes
     * @param L ハッシュ出力 bit長
     * @param xof XOF
     * @param S customization bit string 付加文字
     */
    public ParallelHash(int c, int B, int L, boolean xof, String S) {
        super(c, L, "ParallelHash", S);
        this.B = B;
        this.L = xof ? 0 : L;
        size = B;
        shake = new SHAKE(c, c * 2);
//        z = new PacketA();
        //z.dwrite(SHA3Derived.left_encode(B));
        byte[] zb = SHA3Derived.left_encode(B);
        super.engineUpdate(zb, 0, zb.length);
        n = 0;
    }

    @Override
    public void engineUpdate(byte[] src, int offset, int length) {
        while (size <= length) {
            shake.update(src, offset, size);
            length -= size;
            offset += size;
            byte[] dj = shake.digest();
            super.engineUpdate(dj, 0, dj.length);
            size = B;
            n++;
        }
        if (length > 0) {
            shake.update(src, offset, length);
            size -= length;
        }
    }

    /**
     * digest
     *
     * @return ダイジェスト
     */
    @Override
    public byte[] engineDigest() {
        if (size < B) {
            byte[] dj = shake.digest();
            super.engineUpdate(dj, 0, dj.length);
            n++;
            size = B;
        }
        byte[] a = SHA3Derived.right_encode(n);
        super.engineUpdate(a, 0, a.length);
        a = SHA3Derived.right_encode(L);
        super.engineUpdate(a, 0, a.length);

        n = 0;
        return super.engineDigest();
    }

}
