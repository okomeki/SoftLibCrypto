package net.siisise.security.digest;

/**
 * SHA3-384
 */
public class SHA3384 extends SHA3 {

    static final String OID = hashAlgs + ".9";

    public SHA3384() {
        super(384);
    }
}
