package net.siisise.security.digest;

/**
 * FIPS PUB 202
 * Secure Hash Algorithm KECCAK 256
 * 拡張出力関数 XOF
 * NIST SP 800-185
 */
public class SHAKE256 extends Keccak {

    static final String OID = SHA3.hashAlgs + ".12";
    static final String OIDlen = SHA3.hashAlgs + ".18";

    public SHAKE256(int d) {
        super("SHAKE256(M,"+d+")", 2 * 256, d, (byte) 0x1f);
    }

}
