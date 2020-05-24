package net.siisise.security.digest;

/**
 * SHA3-224
 */
public class SHA3224 extends SHA3 {
    
    static final String OID = hashAlgs + ".7";
    
    public SHA3224() {
        super(224);
    }
}
