package net.siisise.security.stream;

/**
 * NULL 暗号
 */
public class NULL {

    int length;

    NULL() {
        length = 8;
    }

    NULL(int length) {
        this.length = length;
    }

    public int getBlockLength() {
        return length;
    }

    public void init(byte[] key) {
    }

    public byte[] encrypt(byte[] src, int offset) {
        byte[] d = new byte[1];
        d[0] = src[0];
        return d;
    }

    public byte[] decrypt(byte[] src, int offset) {
        byte[] d = new byte[1];
        d[0] = src[0];
        return d;
    }

}
