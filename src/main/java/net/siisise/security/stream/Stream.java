package net.siisise.security.stream;

/**
 * ストリーム系暗号のインターフェース
 * いろいろ未定
 */
public interface Stream {
    
    byte[] encrypt(byte[] src, int offset, int length);    
    byte[] decrypt(byte[] src, int offset, int length);    
}
