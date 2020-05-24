package net.siisise.security.digest;

/**
 *
 */
public class RawSHAKE128 extends Keccak {
    
    public RawSHAKE128(int d) {
        super("RawSHAKE128(J,"+d+")",256,d,(byte)0x07);
    }
    
}
