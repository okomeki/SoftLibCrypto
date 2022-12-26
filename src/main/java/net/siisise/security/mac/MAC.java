package net.siisise.security.mac;

/**
 * Message Authentication Code
 * Mac のどこでも使える版
 */
public interface MAC {

    void init(byte[] key);
    
    default void update(byte[] src) {
        update(src,0,src.length);
    }
    void update(byte[] src, int offset, int length);

    default byte[] doFinal(byte[] src) {
        update(src);
        return doFinal();
    }
    byte[] doFinal();

    /**
     * バイト単位の出力長
     *
     * @return
     */
    int getMacLength();
}
