package net.siisise.security.block;

/**
 * ブロック暗号モジュール.
 * 
 * 暗号化、復号が、固定長で行われる。
 * CFBやOFBを使うとストリームモードでも利用可能。
 */
public interface Block {
    /**
     * ブロック長.
     * ブロック長を外部ブロックに伝え、vectorなどの長さに利用するためのもの。
     * ブロックモード暗号モジュールのみで利用する。
     * @return ビット単位のブロック長.
     */
    int getBlockLength();

    /**
     * 鍵の設定.
     * アルゴリズムによって鍵長は異なる.
     * それぞれ指定の長さに。
     * @param key シークレット鍵 
     */
    void init(byte[] key);
    
    void init(byte[] key, byte[] iv);
    
    /**
     * ブロックモード用
     * @param src
     * @param offset
     * @param length 固定サイズの倍数であること.
     * @return 
     */
    byte[] encrypt(byte[] src, int offset, int length);
    void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length);

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

    /**
     * @deprecated 
     * @param src
     * @param offset
     * @param length
     * @return 
     */
    byte[] decrypt(byte[] src, int offset, int length);
    void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length);
    /**
     * 復号処理.
     * ブロック単位で呼び出される.
     * パディングは考慮しない.
     * @param src ブロックを含んだ配列
     * @param offset ブロックの位置
     * @return 復号されたデータ
     */
    byte[] decrypt(byte[] src, int offset);


}
