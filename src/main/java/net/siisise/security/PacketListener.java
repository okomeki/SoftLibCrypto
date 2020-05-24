package net.siisise.security;

/**
 * 特定の長さのブロック単位で渡してくれる便利機能.
 */
public interface PacketListener {
    void packetOut(byte[] src, int offset, int length);
}
