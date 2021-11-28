package net.siisise.security.block;

/**
 *
 */
public interface EncBlock {

    /**
     * block mode 暗号化用.
     *
     * @param src
     * @param offset
     * @param length 固定サイズの倍数であること. バイト長.
     * @return
     */
    byte[] encrypt(byte[] src, int offset, int length);
    void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length);

    /**
     * ワード単位で処理すれば速いかなと思ったがバイト列から変換が入るとあまり変わらず
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    int[] encrypt(int[] src, int offset, int length);

    /**
     * 1ブロック暗号化処理.
     * 固定長のブロック単位で呼び出される。
     * パディングは考慮しない。
     *
     * @param src ブロックを含んだ列
     * @param offset ブロックの位置
     * @return 暗号化された列
     */
    byte[] encrypt(byte[] src, int offset);
    int[] encrypt(int[] src, int offset);
    
}
