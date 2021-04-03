package net.siisise.security.digest;

import java.security.MessageDigest;

/**
 * 巡回冗長検査.
 *
 * CRC8,16,32と64があるかもしれない.
 * CRC8
 * CRC8-CCITT CRC8-SAE CRC8-ATM CRC8-Dallas/Maxum
 *
 * CRC-32 Wikipedia のものを実装
 */
public class CRC extends MessageDigest {

    static int[] crc = new int[256];

    static {
        for (int i = 0; i < 256; i++) {
            int c = i;
            for (int j = 0; j < 8; j++) {
                c = ((c & 1) != 0) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
            }
            crc[i] = c;
        }
    }

    int c;

    public CRC() {
        super("CRC-32");
        engineReset();
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        for (int i = offset; i < offset + len; i++) {
            c = crc[(c ^ input[i]) & 0xff] ^ (c >>> 8);
//            c = (c << 8) ^ crc[((c >>> 24) ^ input[i]) & 0xff];
        }
    }

    @Override
    protected byte[] engineDigest() {
        c ^= 0xffffffff;
        //engineUpdate(new byte[4], 0, 4);
        byte[] cr = new byte[4];
        cr[0] = (byte) ((c >>> 24) & 0xff);
        cr[1] = (byte) ((c >>> 16) & 0xff);
        cr[2] = (byte) ((c >>> 8) & 0xff);
        cr[3] = (byte) (c & 0xff);
//        System.out.println(Integer.toHexString(c));
        engineReset();
        return cr;
    }

    @Override
    protected void engineReset() {
        c = 0xffffffff;
    }

}
