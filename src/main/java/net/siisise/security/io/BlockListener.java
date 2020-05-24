package net.siisise.security.io;

/**
 * 特定の長さのブロック単位で渡してくれる便利機能。
 * パディングは管理しない。固定長で供給されることを想定している。
 * IOExceptionが発生しない版
 */
public interface BlockListener extends BlockIOListener {
    
    /**
     * データが揃ったらところてんで呼び出される.
     * @param src 元配列
     * @param offset データ位置
     * @param length 固定ブロックサイズ(参考)
     */
    @Override
    void blockWrite(byte[] src, int offset, int length);
    
    @Override
    void flush();
}
