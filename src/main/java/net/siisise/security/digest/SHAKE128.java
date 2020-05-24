package net.siisise.security.digest;

/**
 * FIPS PUB 202
 * Secure Hash Algorithm KECCAK 128
 * 拡張出力関数 XOF
 * SHAKE128
 */
public class SHAKE128 extends Keccak {
    
    static final String OID = SHA3.hashAlgs + ".11";
    static final String OIDlen = SHA3.hashAlgs + ".17";

    public SHAKE128(int d) {
        super("SHAKE128(M,"+d+")", 2 * 128, d, (byte) 0x1f);
    }

}
