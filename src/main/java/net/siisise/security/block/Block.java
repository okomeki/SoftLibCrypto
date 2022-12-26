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
     * 必要な乱数のビット長のめやす.
     * IV, secret, solt などの長さ
     * @return ビット単位の長さの配列
     */
    int[] getParamLength();

    /**
     * 後ろの要素が外側のBlockにかかる.
     * AES CBC の場合、ivをCBCがとり、keyをAESがとる。
     * @param keyandparam シークレット鍵とIVなど
     */
    void init(byte[]... keyandparam);


}
