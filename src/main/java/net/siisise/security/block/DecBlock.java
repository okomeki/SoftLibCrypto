package net.siisise.security.block;

/**
 * ブロック復号系.
 */
public interface DecBlock {
    
    /**
     * 復号処理.
     * @param src 暗号データ列
     * @param offset offset
     * @param length 長さ
     * @return 復号データ
     */
    byte[] decrypt(byte[] src, int offset, int length);
    int[] decrypt(int[] src, int offset, int length);
    long[] decrypt(long[] src, int offset, int length);
    void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length);

    byte[] decrypt(byte[] src);
    int[] decrypt(int[] src);
    long[] decrypt(long[] src);

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
    long[] decrypt(long[] src, int offset);
}
