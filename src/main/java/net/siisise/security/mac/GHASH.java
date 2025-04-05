/*
 * Copyright 2022 Siisise Net.
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
package net.siisise.security.mac;

import net.siisise.io.FIFOPacket;
import net.siisise.lang.Bin;
import net.siisise.lang.ParamThread;
import net.siisise.math.GFRev;

/**
 * GCM 内部用GHASH.
 * 一般的に利用できる暗号化ハッシュ関数ではない.
 * RFC 4543 GMAC の元
 *
 */
public class GHASH implements MAC {

    // hash subkey Cache
    GFRev H;
    private long[] y;

    private FIFOPacket pool;
    // AAD length
    private FIFOPacket lens;
    private long alen;
    
    ParamThread th;

    public GHASH() {
    }

    /**
     * @param H hash subkey
     */
    @Override
    public void init(byte[] H) {
        init(Bin.btol(H), new byte[0]);
    }

    /**
     * 初期化っぽいこと.
     * AADを後付する必要あり?.
     * @param H GHASHの鍵 暗号化した0列
     */
    public void init(long[] H) {
        pool = new FIFOPacket();
        lens = new FIFOPacket();
        this.H = new GFRev(H);
        y = new long[H.length];
    }

    /**
     * 初期値っぽいもの
     *
     * @param H hash subkey
     * @param a AAD 暗号化しない部分
     */
    public void init(long[] H, byte[] a) {
        init(H);
        aad(a);
    }

    /**
     * H を維持したまま他を消す.
     */
    public void clear() {
        y = new long[y.length];
    }

    /**
     * updateとblockClose.
     * @param a AAD 暗号化しない部分
     */
    public void aad(byte[] a) {
        alen = 0;
        update(a, 0, a.length);
        blockClose();
    }

    /**
     * y にブロックを y C_n
     *
     * @param x ブロック列っぽく
     */
    private void xorMul(byte[] x) {
        Bin.xorl(y, x, 0, y.length);
        y = H.mul(y);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        alen += length;
        pool.write(src, offset, length);
        thread();
    }

    /**
     * MAC計算用別スレッドが停止していたら走らせる.
     */
    void thread() {
        ParamThread t = th;
        if ( t == null || !t.isAlive()) {
            try {
                th = new ParamThread(this, "q");
                th.start();
            } catch (NoSuchMethodException ex) {
                throw new IllegalStateException(ex);
            }
        }
    }

    /**
     * MAC計算スレッド.
     * 別スレッドにするだけ.
     */
    public void q() throws java.lang.SecurityException {
        byte[] d = new byte[16];
        while (pool.readable(16)) {
            pool.read(d);
            xorMul(d);
        }
        th = null;
    }

    /**
     * AAD、暗号ブロックの終端.
     */
    void blockClose() {
        Thread t = th;
        if ( t != null ) {
            try {
                t.join();
            } catch (InterruptedException ex) {
                throw new IllegalStateException(ex);
            }
        }
        
        int ps = pool.size();
        if (ps > 0) { // padding
            pool.write(new byte[16 - ps]);
            xorMul(pool.toByteArray());
        }

        lens.write(Bin.toByte(alen * 8));
        alen = 0;
    }

    /**
     *
     * @return tag
     */
    @Override
    public byte[] sign() {
        blockClose();
        xorMul(lens.toByteArray());
        return Bin.ltob(y);
    }

    @Override
    public int getMacLength() {
        return 128 / 8;
    }

}
