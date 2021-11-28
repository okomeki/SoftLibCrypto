package net.siisise.security.block;

/**
 *
 */
public interface DecBlock {
    
    /**
     *
     * @param src
     * @param offset
     * @param length
     * @return
     */
    byte[] decrypt(byte[] src, int offset, int length);
    void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length);
    int[] decrypt(int[] src, int offset, int length);

    /**
     * 復号処理.
     * ブロック単位で呼び出される.
     * パディングは考慮しない.
     *
     * @param src ブロックを含んだ配列
     * @param offset ブロックの位置
     * @return 復号されたデータ
     */
    byte[] decrypt(byte[] src, int offset);
    int[] decrypt(int[] src, int offset);
}
