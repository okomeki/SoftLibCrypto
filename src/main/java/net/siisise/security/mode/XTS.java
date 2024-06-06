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
package net.siisise.security.mode;

import net.siisise.lang.Bin;
import net.siisise.math.GF;
import net.siisise.security.block.Block;

/**
 * NIST SP 800-38E ?
 * IEEE 1619-2018
 * ディスク等暗号化限定、2^20 ブロックまで
 * https://www.cryptrec.go.jp/exreport/cryptrec-ex-2902-2019.pdf
 * @deprecated まだ
 */
@Deprecated
public class XTS extends LongBlockMode {
    int i;
    long[] a;
    GF gf;
    long[] te;

    public XTS(Block block) {
        super(block);
    }
    
    /**
     * K は 標準鍵2つぶん
     * T は 128bitくらいのなにか
     * @param params K, T
     */
    @Override
    public void init(byte[][] params) {
        byte[] k1 = new byte[params[0].length / 2];
        byte[] k2 = new byte[k1.length];
        long[] t = Bin.btol(params[1]);
        System.arraycopy(params[0], 0, k1, 0, k1.length);
        System.arraycopy(params[0], k1.length, k2, 0, k2.length);
        block.init(k2);
        te = block.encrypt(t);
        gf = new GF(128,GF.FF128);
        a = new long[k1.length / 8];
        a[a.length - 1] = 3;
        block.init(k1);
        i = 0;
    }
    
    /**
     * 何ブロック目か指定する
     * @param i 
     */
    public void setCount(int i) {
        this.i = i;
    }

    @Override
    public long[] encrypt(long[] src, int offset) {
        long[] tmp1 = gf.mul(te, gf.pow(a, i++));
        long[] tmp2 = new long[tmp1.length];
        Bin.xor(tmp1, 0, src, offset, tmp2);
        tmp2 = block.encrypt(tmp2);
        return Bin.xorl(tmp2, tmp1);
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        return encrypt(src, offset);
    }
    
}
