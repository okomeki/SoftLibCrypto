package net.siisise.security.digest;

/**
 *
 */
public class RawSHAKE256 extends Keccak {
    
    public RawSHAKE256(int d) {
        super("RawSHAKE256(J,"+d+")",512,d,(byte)0x07);
    }
}
