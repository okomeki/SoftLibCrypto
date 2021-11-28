package net.siisise.security.block;

/**
 * ブロック暗号モジュール.
 *
 * 暗号化、復号が、固定長で行われる。
 * CFBやOFBを使うとストリームモードでも利用可能。
 */
public interface Block extends EncBlock, DecBlock {

    /**
     * Bit block length.
     * ブロック長を外部ブロックに伝え、vectorなどの長さに利用するためのもの。
     * ブロックモード暗号モジュールのみで利用する。
     *
     * @return ビット単位のブロック長.
     */
    int getBlockLength();

    /**
     * 鍵の設定.
     * アルゴリズムによって鍵長は異なる.
     * それぞれ指定の長さに。
     *
     * @param key シークレット鍵
     */
    void init(byte[] key);

    /**
     * 後ろの要素が外側のBlockにかかる.
     * AES CBC の場合、ivをCBCがとり、keyをAESがとる。
     * @param keyandparam シークレット鍵とIVなど
     */
    void init(byte[]... keyandparam);


}
