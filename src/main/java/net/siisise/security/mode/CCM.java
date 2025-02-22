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

import java.util.Arrays;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.block.Block;
import net.siisise.security.mac.CBCMAC;

/**
 * TLS 1.3用 CCM.
 * NIST SP 800-38C.
 * RFC 3610 Counter with CBC-MAC (CCM).
 * CTR と CBC-MAC の K は同じ
 * 
 * nonce から L を決める
 */
public class CCM extends StreamMode implements StreamAEAD {

    private CBCMAC cbc;
    private CTR ctr;
    /**
     * The associated data String
     */
    private Packet a;
//    private byte[] ac;
    // ivの元
//    private int flag;
//    private int l;
//    private int m;
    private byte[][] upkey;
    private byte[] iv;
    
    private Packet x;
    
    public CCM(Block block) {
        this(block, 4);
    }

    /**
     * CCMの初期化.
     * K: 鍵
     * nonce: ivのもと
     * L: 長さフィールドのサイズ octets
     * N: nonce 15-L octets
     * m: message
     * a: 追加データ (MAC出力へ反映のみ)
     * 
     * L は nonceサイズから決められるので省略する
     * @param block
     * @param M authentication field の octet数 4,6,8,10,12,14,16
     * 
     */
    public CCM(Block block, int M) {
        super(block);
        if ( M < 4 || M > 16 || (M % 2) != 0) {
            throw new IllegalStateException();
        }
        if (block.getBlockLength() != 128 ) {
            throw new SecurityException("block length");
        }
        iv = new byte[16];
        // flag
        // M L
        int Mbit = (M - 2) / 2;
        iv[0] |= Mbit << 3;
        x = new PacketA();
    }

    static private final byte[] A4 = new byte[] {(byte)0xff,(byte)0xfe};
    static private final byte[] A8 = new byte[] {(byte)0xff,(byte)0xff};
    
    /**
     * nonce と A: The associated data string
     * M: 認証フィールドのサイズ 4,6,8,10,12,14,16
     * L: 長さフィールドのサイズ 2から8オクテット nonceの長さから決める
     * 
     * @param params (block key,) nonce N, associated data A
     */
    @Override
    public void init(byte[]... params) {
//        block.init(in(2,params));
        int size = params.length - block.getParamLength().length;
        upkey = in(size, params);
        super.init(upkey); // ctrで置き換え?
        
        byte[] nonce = params[params.length - size]; // N
        int L = 15 - nonce.length;
        if ( L < 2 || L > 8 ) {
            throw new IllegalStateException("nonce length");
        }

        // 暗号側 CTR
        ctr = new CTR(block);
        byte[] ctrIV = new byte[16];
        ctrIV[0] |= L-1;
        ctrIV[15] = 1;
        System.arraycopy(nonce, 0, ctrIV, 1, nonce.length);
        byte[][] ctrParams = new byte[][] {params[0], ctrIV};
        ctr.init(ctrParams);

        // MAC
        iv[0] |= ctrIV[0]; // flag
        System.arraycopy(nonce, 0, iv, 1, nonce.length);

        if ( size > 1) { // nonceの他にaがある
            byte[] ac = params[params.length - 1];
            if ( ac.length > 0 ) {
                iv[0] |= 0x40;
                a = new PacketA(ac);
                long al = a.length();
                byte[] ab = Bin.ltob(new long[] {al});
                if ( al <= 0xfeff ) {
                    a.backWrite(ab, 6, 2);
                } else if (al < 0x100000000l) {
                    a.backWrite(ab, 4, 4);
                    a.backWrite(A4);
                } else {
                    a.backWrite(ab);
                    a.backWrite(A8);
                }
                int padlen = 16 - (int)(a.length() % 16);
                if ( padlen < 16 ) {
                    a.write(new byte[padlen]);
                }
            } else {
                a = null;
            }
        } else {
            a = null;
        }
    
    }
    
    /**
     * 
     * C = (P ^ MSB Plen(S)) || (T ^ MSB Tlen(S0))
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        x.write(src, offset, length);
        return ctr.encrypt(src, offset, length);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        byte[] t = ctr.decrypt(src, offset, length);
        x.write(t);
        return t;
    }

    @Override
    public byte[] tag() {
        return doFinalEncrypt();
    }

    @Override
    public byte[] doFinalEncrypt(byte[] src, int offset, int length) {
        byte[] ret = encrypt(src, offset, length);
        
        byte[] mac = doMac();

        x.write(ret);
        x.write(mac);
        return x.toByteArray();
    }

    @Override
    public byte[] doFinalDecrypt(byte[] src, int offset, int length) {
        Packet tmp = new PacketA();
        tmp.write(src, offset, length);
        int M = ((iv[0] >>> 3) & 0x07) * 2 + 2;
        byte[] dmac = new byte[M];
        tmp.backRead(dmac);
        byte[] d = new byte[length - M];
        tmp.read(d);
        byte[] ret = decrypt(d, 0, d.length);

        byte[] mac = doMac();
        if ( !Arrays.equals(mac, dmac)) {
            throw new IllegalStateException();
        }
        return ret;
    }

    private byte[] doMac() {
        // 本文の長さをIVに埋め込み
        long len = x.length();
        byte[] lb = Bin.ltob(new long[] {0l, len});
        int L = (((int)(iv[0] & 0x07)) + 1);
        System.arraycopy(lb, 16 - L, iv, 16 - L, L);

        cbc = new CBCMAC(block); // init不足
        cbc.update(iv); // B_0
        if ( a != null ) {
            byte[] b = a.toByteArray();
            cbc.update(b,0,b.length);
        }
        cbc.update(x.toByteArray());
        int padlen = 16 - (int)(len % 16);
        if ( padlen < 16 ) {
            cbc.update(new byte[padlen]);
        }
        byte[] T = cbc.doFinal();

        int M = ((iv[0] >>> 3) & 0x07) * 2 + 2;
        iv[0] &= 0x07;
        for (int i = 16 - L; i < 16; i++) {
            iv[i] = 0;
        }
        ctr.init(upkey[0], iv);
        byte[] S_0 = ctr.encrypt(T);
        return Arrays.copyOf(S_0, M);
    }
    
}
