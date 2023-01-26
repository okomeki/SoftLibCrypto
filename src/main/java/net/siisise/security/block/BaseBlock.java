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
 *
 */
public abstract class BaseBlock implements Block {
    
    @Override
    public int[] getParamLength() {
        return new int[] { getBlockLength() };
    }

    /**
     * byte[]をint[]に変換する.
     * @param src byte列
     * @return int列
     */
    public static final int[] btoi(final byte[] src) {
        int t = 0;
        int dl = src.length / 4;
        int[] dst = new int[dl];
        for (int i = 0; i < dst.length; i++, t+= 4) {
            dst[i]
                    = ( src[t]         << 24)
                    | ((src[t+1] & 0xff) << 16)
                    | ((src[t+2] & 0xff) <<  8)
                    |  (src[t+3] & 0xff);
        }
        return dst;
    }

    /**
     * byte[]をint[]に変換する.
     * @param src byte列
     * @return int列
     */
    public static final long[] btol(final byte[] src) {
        int t = 0;
        long[] dst = new long[src.length / 8];
        for (int i = 0; i < dst.length; i++, t+= 8) {
            dst[i]
                    = (((long)src[t])    << 56)
                    | ((((long)src[t+1]) & 0xff) << 48)
                    | ((((long)src[t+2]) & 0xff) << 40)
                    | ((((long)src[t+3]) & 0xff) << 32)
                    | ((((long)src[t+4]) & 0xff) << 24)
                    | ((((long)src[t+5]) & 0xff) << 16)
                    | ((((long)src[t+6]) & 0xff) <<  8)
                    |  (((long)src[t+7]) & 0xff);
        }
        return dst;
    }

    public static byte[] itob(final int[] src) {
        byte[] ss = new byte[src.length*4];
        for (int i = 0; i < src.length; i++) {
            int l = i*4;
            ss[l++] = (byte) (src[i] >> 24);
            ss[l++] = (byte) (src[i] >> 16);
            ss[l++] = (byte) (src[i] >>  8);
            ss[l  ] = (byte)  src[i]       ;
        }
        return ss;
    }
    
    public static byte[] ltob(final long[] src) {
        byte[] ds = new byte[src.length*8];
        for (int i = 0; i < src.length; i++) {
            long s = src[i];
            int l = i*8;
            ds[l  ] = (byte)(s >> 56);
            ds[l+1] = (byte)(s >> 48);
            ds[l+2] = (byte)(s >> 40);
            ds[l+3] = (byte)(s >> 32);
            ds[l+4] = (byte)(s >> 24);
            ds[l+5] = (byte)(s >> 16);
            ds[l+6] = (byte)(s >>  8);
            ds[l+7] = (byte)(s      );
        }
        return ds;
    }

    public static final int[] ltoi(final long[] src) {
        int[] ss = new int[src.length*2];
        for (int i = 0; i < src.length; i++) {
            int l = i*2;
            ss[l+1] = (int)src[i];
            ss[l] = (int)(src[i] >> 32);
        }
        return ss;
    }

    public static final long[] itol(final int[] src) {
        long[] ss = new long[src.length/2];
        for (int i = 0; i < ss.length; i++) {
            ss[i] = (((long)src[i*2]) << 32)
                  | (((long)src[i*2+1]) & 0xffffffffl);
        }
        return ss;
    }

    /**
     * 
     * @param src
     * @param offset
     * @param len
     * @return 
     */
    public static final byte[] itob(final int[] src, int offset, int len) {
        byte[] ss = new byte[len * 4];
        int l = 0;
        for (int i = len; i > 0; i--) {
            int v = src[offset++];
            ss[l++] = (byte) (v >> 24);
            ss[l++] = (byte) (v >> 16);
            ss[l++] = (byte) (v >>  8);
            ss[l++] = (byte)  v       ;
        }
        return ss;
    }
    
    public static final int[] btoi(final byte[] src, int offset, int length) {
        int[] dst = new int[length];
        int t = offset;
        for (int i = 0; i < dst.length; i++) {
            dst[i]
                    = ( src[t]         << 24)
                    | ((src[t+1] & 0xff) << 16)
                    | ((src[t+2] & 0xff) <<  8)
                    |  (src[t+3] & 0xff);
            t+=4;
        }
        return dst;
    }

    /**
     * 
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    public static final long[] btol(final byte[] src, int offset, int length) {
        long[] dst = new long[length];
        for (int i = 0; i < dst.length; i++, offset+=8) {
            dst[i]
                    = (((long) src[offset])           << 56)
                    | (((long)(src[offset+1] & 0xff)) << 48)
                    | (((long)(src[offset+2] & 0xff)) << 40)
                    | (((long)(src[offset+3] & 0xff)) << 32)
                    | (((long)(src[offset+4] & 0xff)) << 24)
                    | (((long)(src[offset+5] & 0xff)) << 16)
                    | (((long)(src[offset+6] & 0xff)) <<  8)
                    |  ((long)(src[offset+7] & 0xff));
        }
        return dst;
    }

    public static final int[] ltoi(final long[] src, int offset, int length) {
        int[] dst = new int[length];
        int t = offset;
        for (int i = 0; i < dst.length; i+=2) {
            dst[i  ] = (int)(src[t] >> 32);
            dst[i+1] = (int)(src[t++] & 0xffffffffl);
        }
        return dst;
    }

    /**
     * 
     * @param src
     * @param offset
     * @param srclen srclen
     * @return 
     */
    public static byte[] ltob(final long[] src, int offset, int srclen) {
        byte[] ss = new byte[srclen * 8];
        int l = 0;
        for (int i = srclen; i > 0; i--) {
            long v = src[offset++];
            ss[l  ] = (byte) (v >> 56);
            ss[l+1] = (byte) (v >> 48);
            ss[l+2] = (byte) (v >> 40);
            ss[l+3] = (byte) (v >> 32);
            ss[l+4] = (byte) (v >> 24);
            ss[l+5] = (byte) (v >> 16);
            ss[l+6] = (byte) (v >>  8);
            ss[l+7] = (byte)  v       ;
            l+=8;
        }
        return ss;
    }

    /**
     * 
     * @param src 転送元
     * @param offset 転送元位置
     * @param dst 転送先
     * @param length 転送先長
     */
    public static final void btol(final byte[] src, int offset, long[] dst, int length) {
        for (int i = 0; i < length; i++, offset+= 8) {
            dst[i]
                    = ( (long)src[offset]         << 56)
                    | (((long)src[offset+1] & 0xff) << 48)
                    | (((long)src[offset+2] & 0xff) << 40)
                    | (((long)src[offset+3] & 0xff) << 32)
                    | (((long)src[offset+4] & 0xff) << 24)
                    | (((long)src[offset+5] & 0xff) << 16)
                    | (((long)src[offset+6] & 0xff) <<  8)
                    |  ((long)src[offset+7] & 0xff);
        }
    }

    /**
     * 
     * @param src
     * @param offset
     * @param dst
     * @param length 
     */
    public static final void itol(final int[] src, int offset, long[] dst, int length) {
        int t = offset;
        for (int i = 0; i < length; i++) {
            dst[i]
                    = ( ((long)src[t])        << 32)
                    |  ((long)src[t+1] & 0xffffffffl);
            t+=2;
        }
    }

    /**
     * byte[]をint[]に変換する.
     * 
     * @param src バイト列
     * @param offset 位置
     * @param dst 戻りint列
     * @param length int長
     */
    public static void btoi(final byte[] src, int offset, int[] dst, int length) {
        int t = offset;
        for (int i = 0; i < length; i++) {
            dst[i]
                    = ( src[t]         << 24)
                    | ((src[t+1] & 0xff) << 16)
                    | ((src[t+2] & 0xff) <<  8)
                    |  (src[t+3] & 0xff);
            t+=4;
        }
    }
    
    /**
     * 
     * @param src
     * @param offset
     * @param dst
     * @param length 
     */
    public static void ltoi(final long[] src, int offset, int[] dst, int length) {
        int t = offset;
        for (int i = 0; i < length; i+=2) {
            dst[i  ] = (int)(src[t] >> 32);
            dst[i+1] = (int)(src[t++] & 0xffffffffl);
        }
    }
    
    /**
     * int[]をbyte[]に戻す.
     * @param src
     * @param ss
     * @param doffset
     * @return 
     */
    public static byte[] itob(final int[] src, byte[] ss, int doffset) {
        for (int i = 0; i < src.length; i++) {
            int l = doffset + i*4;
            ss[l++] = (byte) (src[i] >> 24);
            ss[l++] = (byte) (src[i] >> 16);
            ss[l++] = (byte) (src[i] >>  8);
            ss[l  ] = (byte)  src[i]       ;
        }
        return ss;
    }

    /**
     * 
     * @param src
     * @param ss
     * @param doffset
     * @return 
     */
    public static byte[] ltob(final long[] src, byte[] ss, int doffset) {
        for (int i = 0; i < src.length; i++) {
            int l = doffset + i*8;
            ss[l  ] = (byte) (src[i] >> 56);
            ss[l+1] = (byte) (src[i] >> 48);
            ss[l+2] = (byte) (src[i] >> 40);
            ss[l+3] = (byte) (src[i] >> 32);
            ss[l+4] = (byte) (src[i] >> 24);
            ss[l+5] = (byte) (src[i] >> 16);
            ss[l+6] = (byte) (src[i] >>  8);
            ss[l+7] = (byte)  src[i]       ;
        }
        return ss;
    }

    /**
     * 暗号化.
     * @param src 元ブロック
     * @return 
     */
    @Override
    public byte[] encrypt(byte[] src) {
        return encrypt(src, 0, src.length);
    }

    @Override
    public int[] encrypt(int[] src) {
        return encrypt(src, 0, src.length);
    }

    @Override
    public long[] encrypt(long[] src) {
        return encrypt(src, 0, src.length);
    }

    @Override
    public byte[] decrypt(byte[] src) {
        return decrypt(src, 0, src.length);
    }

    @Override
    public int[] decrypt(int[] src) {
        return decrypt(src, 0, src.length);
    }

    @Override
    public long[] decrypt(long[] src) {
        return decrypt(src, 0, src.length);
    }

    /**
     * 復号処理.
     * 
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        int blen = getBlockLength() / 8;
        int len = length / blen;
        byte[] dec = new byte[length];
        byte[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }
    
    /**
     * 復号処理.
     * 
     * @param src
     * @param offset
     * @param length
     * @return
     */
    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        int blen = getBlockLength() / 32;
        int len = length / blen;
        int[] dec = new int[length];
        int[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }

    @Override
    public long[] decrypt(long[] src, int offset, int length) {
        int blen = getBlockLength() / 64;
        int len = length / blen;
        long[] dec = new long[length];
        long[] bdec;
        int to = 0;
        for ( int i = 0; i < len; i++ ) {
            bdec = decrypt(src, offset);
            System.arraycopy(bdec, 0, dec, to, blen);
            offset += blen;
            to += blen;
        }
        return dec;
    }

}
