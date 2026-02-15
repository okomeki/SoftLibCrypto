/*
 * Copyright 2026 okome.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.siisise.security.math;

import java.math.BigInteger;
import net.siisise.security.ec.ECCurvet;
import net.siisise.security.ec.EllipticCurve;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class BIGFTest {
    
    public BIGFTest() {
    }

    /**
     * Test of add method, of class BIGF.
     */
    @Test
    public void testAdd() {
        System.out.println("add");
        BigInteger p = BigInteger.valueOf(0x11b);
        BIGF gf = new BIGF(p);
        BigInteger a = BigInteger.valueOf(0x03);
        BigInteger b = BigInteger.valueOf(0x01);
        BigInteger expResult = BigInteger.valueOf(0x02);
        BigInteger result = gf.add(a, b);
        assertEquals(expResult, result);
    }

    /**
     * Test of mul method, of class BIGF.
     */
    @Test
    public void testMul() {
        System.out.println("mul");
        BigInteger p = BigInteger.valueOf(0x11b);
        BigInteger a = BigInteger.valueOf(0x02);
        BigInteger b = BigInteger.valueOf(0x03);
        BIGF gf = new BIGF(p);
        
        BigInteger expResult = BigInteger.valueOf(0x6);
        BigInteger result = gf.mul(a, b);
        assertEquals(expResult, result);
    }

    /**
     * Test of x method, of class BIGF.
     */
    @Test
    public void testX() {
        System.out.println("x");
        BIGF gf = new BIGF(BigInteger.valueOf(0x11b));
        BigInteger a = BigInteger.valueOf(0x80);
        BigInteger expResult = BigInteger.valueOf(0x1b);
        BigInteger result = gf.x(a);
        assertEquals(expResult, result);
    }

    @Test
    public void testX2() {
        System.out.println("x2");
        ECCurvet k163 = EllipticCurve.K163;
        BigInteger p = k163.p; //new BigInteger("0", 16);
        BigInteger n = k163.n; //new BigInteger("0", 16);
        BIGF gf = new BIGF(p, n);
        BigInteger i2 = gf.inv(BigInteger.TWO);
        System.out.println(gf.mul(i2, BigInteger.TWO).toString(16));
    }

    @Test
    public void testGF2_4() {
        System.out.println("GF(2^4)");
        BIGF gf = new BIGF(BigInteger.valueOf(0x13),BigInteger.valueOf(15));
        BigInteger n = BigInteger.ONE;
        for (int i = 0; i < 16; i++) {
            System.out.print("src: " + n.toString(16));
            BigInteger in = gf.inv(n);
            System.out.print(" inv: " + in.toString(16));
            System.out.print(" x  : " + gf.mul(n, in));
            assertEquals(BigInteger.ONE, gf.mul(n,in));
            System.out.println(" pow2:" + gf.pow(BigInteger.TWO, BigInteger.valueOf(i)));
            System.out.println("pow3:" + gf.pow(n, BigInteger.TWO));
            n = gf.x(n);
        }

    }
    
    /**
     * Test of r method, of class BIGF.
     */
    @Test
    public void testR() {
        System.out.println("r");
        BigInteger a = BigInteger.ONE;
        BIGF gf = new BIGF(BigInteger.valueOf(0x11b));
        BigInteger expResult = BigInteger.valueOf(0x8d);
        BigInteger result = gf.r(a);
        assertEquals(expResult, result);
    }

    /**
     * Test of pow method, of class BIGF.
     */
    @Test
    public void testPow() {
        System.out.println("pow");
        BigInteger a = BigInteger.TWO;
        BigInteger n = BigInteger.valueOf(8);
        BIGF instance = new BIGF(BigInteger.valueOf(0x11b));
        BigInteger expResult = BigInteger.valueOf(0x1b);
        BigInteger result = instance.pow(a, n);
        assertEquals(expResult, result);
    }

    /**
     * Test of inv method, of class BIGF.
     */
    @Test
    public void testInv() {
        System.out.println("inv");
        BIGF gf = new BIGF(BigInteger.valueOf(0x11b));
        BigInteger a = BigInteger.valueOf(0x53);
        BigInteger expResult = BigInteger.valueOf(0xca);
        BigInteger result = gf.inv(a);
        System.out.println("invv >>>" + result.toString(16));
        assertEquals(expResult, result);
    }
    
}
