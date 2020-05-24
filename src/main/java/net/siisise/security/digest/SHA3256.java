package net.siisise.security.digest;

/**
 * SHA3-256
 */
public class SHA3256 extends SHA3 {

    static final String OID = hashAlgs + ".8";

    public SHA3256() {
        super(256);
    }
}
