package net.siisise.security;

import org.junit.jupiter.api.Test;

/**
 *
 */
public class GFTest {
    
    public GFTest() {
        
    }
    
    
    @Test
    public void testRGF() {
        
        int[] gf = new int[256];
        int[] rgf = new int[256];
        
        for (int i = 0; i < 256; i++ ) {
            gf[i] = (i << 1) ^ ((i >> 8) * 0x11b);
            
            rgf[i] = (i >> 1) ^ ((i & 1) * 0x1b);
            
        }
        
        for (int i = 0; i < 256; i++) {
            System.out.println("i  : " + i);
            System.out.println("GF : " + gf[i]);
            System.out.println("RGF: " + rgf[i]);
        }
    }
}
