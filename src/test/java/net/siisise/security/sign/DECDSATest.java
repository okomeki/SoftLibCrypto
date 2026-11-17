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
package net.siisise.security.sign;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import net.siisise.iso.asn1.tag.ASN1DERFormat;
import net.siisise.lang.Bin;
import net.siisise.security.digest.SHA1;
import net.siisise.security.digest.SHA256;
import net.siisise.security.ec.ECCurvet;
import net.siisise.security.ec.EllipticCurve;
import net.siisise.security.key.ECDSAPrivateKey;
import net.siisise.security.key.ECDSAPublicKey;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 * RFC 6979 決定論的ECDSA A.2
 */
public class DECDSATest {

    public DECDSATest() {
    }

    @Test
    public void testA11() {
        System.out.println("RFC 6979 A.1.");

        System.out.println("A.1.1. Key Pair");
        ECCurvet K163 = EllipticCurve.K163;
        BigInteger q = K163.getOrder(); // n
        byte[] x = Bin.toByteArray("009A4D6792295A7F730FC3F2B49CBC0F62E862272F"); // 秘密鍵
        byte[] h1 = Bin.toByteArray("AF2BDBE1AA9B6EC1E2ADE1D694F41FC71A831D0268E9891562113D8A62ADD1BF");
        byte[] Ux = Bin.toByteArray("079AEE090DB05EC252D5CB4452F356BE198A4FF96F");
        byte[] Uy = Bin.toByteArray("0782E29634DDC9A31EF40386E896BAA18B53AFA5A3");
        byte[] xo = Bin.toByteArray("01795EDF0D54DB760F156D0DAC04C0322B3A204224");

        ECDSAPrivateKey prv = new ECDSAPrivateKey(EllipticCurve.K163, x);
        BigInteger N = prv.getCurve().getN();
        // int qlen = N.bitLength();
        Deterministic de = new Deterministic(N);

        System.out.println("q:" + K163.getOrder().toString(16));
        System.out.println("N:" + N.toString(16));
        System.out.println("S:" + prv.getS().toString(16));
        ECDSAPublicKey pub = prv.getPublicKey();
        EllipticCurve.ECPoint Y = pub.getY();
        assertEquals(new BigInteger(Ux), Y.getX());
        assertEquals(new BigInteger(Uy), Y.getY());

        System.out.println();
        System.out.println("A.1.2. Generation of k : kの生成");

        SHA256 sha = new SHA256();
        byte[] h = sha.digest("sample".getBytes());
        assertArrayEquals(h1, h, "A.1.2. Hash");
        
        ASN1DERFormat format = new ASN1DERFormat();
        DECDSA dec = new DECDSA(prv, sha);
        dec.update("sample".getBytes());
        byte[] sign1 = dec.sign(format);
        
        BigInteger k = DECDSA.genK(h, sha, prv.getS(), q);
        System.out.println("k:" + k.toString(16));
        String exK = "23af4074c90a02b3fe61d286d5c87f425e6bdd81b";
        assertEquals(exK, k.toString(16));
        
        System.out.println();
        System.out.println("A.1.3. 署名");
        byte[] sign2 = dec.sign(h1, k);
        byte[] exDERSign = Bin.toByteArray("302e02150113a63990598a3828c407c0f4d2438d990df99a7f021501313a2e03f5412ddb296a22e2c455335545672d9f");
        byte[] exSign2 = Bin.toByteArray("0113a63990598a3828c407c0f4d2438d990df99a7f01313a2e03f5412ddb296a22e2c455335545672d9f");
        System.out.println("sign1: " + Bin.toHex(sign1));
        System.out.println("sign2: " + Bin.toHex(sign2));
        assertArrayEquals(exDERSign,sign1);
        assertArrayEquals(exSign2,sign2);

        byte[] xbin = de.int2octets(prv.getS());
//        byte[] xbin = PKCS1.I2OSP(prv.getS(), (qlen+7)/8);
        assertArrayEquals(x, xbin, "秘密鍵");

        System.out.println("H1:" + Bin.toHex(h1));

        byte[] hbin = de.bits2octets(h1);
        System.out.println(Bin.toHex(hbin));
        assertArrayEquals(xo, hbin, "A.1.2. bits2octets");

    }

    /**
     * Test of sign method, of class DECDSA.
     */
    @Test
    public void testSign() {
        System.out.println("sign");
        byte[] key = Bin.toByteArray("6FAB034934E4C0FC9AE67F5B5659A9D7D1FEFD187EE09FD4");
        ECDSAPrivateKey prv = new ECDSAPrivateKey(EllipticCurve.P192, key);
        ECDSAPublicKey pub = prv.getPublicKey();
        EllipticCurve.ECPoint pubPoint = pub.getY();
        assertEquals("AC2C77F529F91689FEA0EA5EFEC7F210D8EEA0B9E047ED56".toLowerCase(), pubPoint.getX().toString(16));
        assertEquals("3BC723E57670BD4887EBC732C523063D0A7C957BC97C1C43".toLowerCase(), pubPoint.getY().toString(16));

        SHA1 sha = new SHA1();
        sha.update("sample".getBytes(StandardCharsets.UTF_8));
        byte[] H = sha.digest();
        System.out.println(Bin.toHex(H));

        ECDSA decdsa = new DECDSA(prv, new SHA1());
        decdsa.update("sample".getBytes(StandardCharsets.UTF_8));
        byte[] expResult = Bin.toByteArray("57A22B07DEA9530F8DE9471B1DC6624472E8E2844BC25B64");
        byte[] result = decdsa.pairDec(decdsa.sign())[1].toByteArray();
        System.out.println("sign:" + Bin.toHex(result));
        System.out.println("exp :" + Bin.toHex(expResult));
        assertArrayEquals(expResult, result);
    }

}
