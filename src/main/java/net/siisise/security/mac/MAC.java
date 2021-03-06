package net.siisise.security.mac;

/**
 * Message Authentication Code
 * Mac のどこでも使える版
 */
public interface MAC {
    void update(byte[] src);
    void update(byte[] src, int offset, int length);

    /**
     * バイト単位の出力長
     * @return 
     */
    int getMacLength();
}
