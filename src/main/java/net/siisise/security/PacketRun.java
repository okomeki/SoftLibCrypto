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
package net.siisise.security;

/**
 * 整流器. 中継を減らしたいだけ
 */
public class PacketRun {

    private final byte[] tmp;
    private final int max;
    private final PacketListener listener;
    private int offset;

    public PacketRun(int max, PacketListener lis) {
        this.max = max;
        tmp = new byte[max];
        listener = lis;
    }

    public void write(byte[] input) {
        write(input, 0, input.length);
    }

    public void write(byte[] src, int offset, int length) {
        if (this.offset > 0) {
            if (this.offset + length >= max) {
                int size = max - this.offset;
                System.arraycopy(src, offset, tmp, this.offset, size);
                offset += size;
                length -= size;
                listener.packetOut(tmp, 0, max);
                this.offset = 0;
            } else { // あわせても足りない
                System.arraycopy(src, offset, tmp, this.offset, length);
                this.offset += length;
                return;
            }
        }

        while (length >= max) {
            listener.packetOut(src, offset, max);
            offset += max;
            length -= max;
        }
        if (length > 0) {
            System.arraycopy(src, offset, tmp, 0, length);
            this.offset = length;
        }
    }

    public int size() {
        return offset;
    }

    public static void writeBig(int[] w, int offset, byte[] input, int inoffset, int length) {
        for (int i = 0; i < length; i++) {
            int of = offset + i * 4;
            w[i] = ((input[of] & 0xff) << 24)
                    + ((input[of + 1] & 0xff) << 16)
                    + ((input[of + 2] & 0xff) << 8)
                    + (input[of + 3] & 0xff);
        }
    }

    public static void writeLittle(int[] w, int offset, byte[] input, int inoffset, int length) {
        for (int i = 0; i < length; i++) {
            int of = offset + i * 4;
            w[i] = ((input[of + 3] & 0xff) << 24)
                    + ((input[of + 2] & 0xff) << 16)
                    + ((input[of + 1] & 0xff) << 8)
                    + (input[of] & 0xff);
        }
    }

    public static void writeBig(long[] w, int offset, byte[] input, int inoffset, int length) {
        for (int i = 0; i < length; i++) {
            int of = inoffset + i * 8;
            w[offset + i] = (((long) input[of] & 0xff) << 56)
                    + (((long) input[of + 1] & 0xff) << 48)
                    + (((long) input[of + 2] & 0xff) << 40)
                    + (((long) input[of + 3] & 0xff) << 32)
                    + (((long) input[of + 4] & 0xff) << 24)
                    + ((input[of + 5] & 0xff) << 16)
                    + ((input[of + 6] & 0xff) << 8)
                    + (input[of + 7] & 0xff);
        }
    }

    public static void writeLittle(long[] w, int offset, byte[] input, int inoffset, int length) {
        for (int i = 0; i < length; i++) {
            int of = inoffset + i * 8;
            w[offset + i] = (((long) (input[of + 7] & 0xff)) << 56)
                    + (((long) (input[of + 6] & 0xff)) << 48)
                    + (((long) (input[of + 5] & 0xff)) << 40)
                    + (((long) (input[of + 4] & 0xff)) << 32)
                    + (((long) (input[of + 3] & 0xff)) << 24)
                    + ((input[of + 2] & 0xff) << 16)
                    + ((input[of + 1] & 0xff) << 8)
                    + (input[of] & 0xff);
        }
    }
}
