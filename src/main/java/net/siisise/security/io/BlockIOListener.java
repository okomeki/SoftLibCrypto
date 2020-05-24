package net.siisise.security.io;

import java.io.IOException;

/**
 * 特定の長さのブロック単位で渡してくれる便利機能。
 * パディングは管理しない。固定長で供給されることを想定している。
 * IOException が発生する版
 */
public interface BlockIOListener {
    
    /**
     * 必要なブロック長.
     * @return ビット長
     */
    int getBitBlockLength();
    
    /**
     * データが揃ったらところてんで呼び出される.
     * @param src 元配列
     * @param offset データ位置
     * @param length 固定ブロックサイズ(参考)
     * @throws java.io.IOException
     */
    void blockWrite(byte[] src, int offset, int length) throws IOException;
    
    void flush() throws IOException;
    
    /**
     * flush() で呼ばれず closeで呼ばれる 仮Interface
     * @param src
     * @param size max - offset で 1以上 maxまでくらい
     * @throws IOException 
     */
    void blockFlush(byte[] src, int size) throws IOException;

    void close() throws IOException;
}
