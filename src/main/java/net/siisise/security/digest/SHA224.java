package net.siisise.security.digest;

/**
 * SHA-224.
 * FIPS PUB 180-2
 * RFC 3874
 */
public class SHA224 extends SHA256 {

    public static String OBJECTIDENTIFIER = "2.16.840.1.101.3.4.2.4";

    static int[] IV224 = {
        0xc1059ed8,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4
    };
    
    public SHA224() {
        super("SHA-224", IV224);
    }
    
    @Override
    protected int engineGetDigestLength() {
        return 28;
    }

}
