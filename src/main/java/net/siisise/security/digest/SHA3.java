package net.siisise.security.digest;

/**
 * SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions (FIPS PUB 202).
 * Secure Hash Algorithm-3 (SHA-3) family.
 * w=64 (long) で最適化したもの
 * SHA3-224, SHA3-256, SHA3-384, SHA3-512 に対応
 * little endian ?
 */
public class SHA3 extends Keccak {

    static final String nistAlgorithms = ".4";
    static final String hashAlgs = nistAlgorithms + ".2";

    /**
     * r は 1152,1088,832,576
     *
     * @param n 出力長 224,256,384,512
     */
    public SHA3(int n) {
        super("SHA3-", 2 * n, n, (byte) 0x06);
    }

}
