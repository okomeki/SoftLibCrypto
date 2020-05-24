package net.siisise.security.digest;

/**
 * SHA3-512
 */
public class SHA3512 extends SHA3 {

    static final String OID = hashAlgs + ".10";

    public SHA3512() {
        super(512);
    }
}
