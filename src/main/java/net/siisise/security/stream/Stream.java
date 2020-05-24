package net.siisise.security.stream;

/**
 *
 */
public interface Stream {
    
    byte[] encrypt(byte[] src, int offset, int length);    
    byte[] decrypt(byte[] src, int offset, int length);    
}
