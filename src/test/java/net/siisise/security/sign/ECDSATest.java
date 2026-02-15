/*
 * Copyright 2025 okome.
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
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import net.siisise.ietf.pkcs1.PKCS1;
import net.siisise.lang.Bin;
import net.siisise.security.digest.SHA256;
import net.siisise.security.digest.SHA3;
import net.siisise.security.digest.SHA3224;
import net.siisise.security.digest.SHA3256;
import net.siisise.security.ec.ECCurvep;
import net.siisise.security.ec.ECCurvet;
import net.siisise.security.ec.EllipticCurve;
import net.siisise.security.key.ECDSAKeyGen;
import net.siisise.security.key.ECDSAPrivateKey;
import net.siisise.security.key.ECDSAPublicKey;
import net.siisise.security.math.BIGF;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * ECDSAなテスト.
 */
public class ECDSATest {

    public ECDSATest() {
    }

    /**
     * Test of toCurve method, of class ECDSA.
     */
    @Test
    public void testToCurve() {
        System.out.println("toCurve");
        ECParameterSpec spec = null;
        ECCurvep expResult = null;
//        EllipticCurve.ECCurvep result = ECDSA.toCurve(spec);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of toSpec method, of class ECDSA.
     */
    @Test
    public void testToSpec() {
        System.out.println("toSpec");
        ECCurvep curve = null;
        ECParameterSpec expResult = null;
//        ECParameterSpec result = ECDSA.toSpec(curve);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * FIPS PUB 186-5 6.4.1.
     */
    @Test
    public void testVector1() {
        System.out.println("Vector1 P256");
//        byte[] d  = Bin.toByteArray("e5ce89a34adddf25ff3bf1ffe6803f57d0220de3118798ea");
        byte[] H = Bin.toByteArray("A41A41A12A799548211C410C65D8133AFDE34D28BDD542E4B680CF2899C8A8C4"); // Hash(M)
        byte[] E = Bin.toByteArray("A41A41A12A799548211C410C65D8133AFDE34D28BDD542E4B680CF2899C8A8C4"); // 切り詰めた値
        byte[] K = Bin.toByteArray("7A1A7E52797FC8CAAA435D2A4DACE39158504BF204FBE19F14DBB427FAEE50AE"); // 乱数? どめいんぱらめーた? 乱数
        byte[] Kinv = Bin.toByteArray("62159E5BA9E712FB098CCE8FE20F1BED8346554E98EF3C7C1FC3332BA67D87EF"); // inv n
        byte[] Rx = Bin.toByteArray("2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F"); // 公開鍵 R Q
        byte[] Ry = Bin.toByteArray("3CE76603264661EA2F602DF7B4510BBC9ED939233C553EA5F42FB3F1338174B5");
        byte[] R = Bin.toByteArray("2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F"); // r 署名1
        byte[] D = Bin.toByteArray("C477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96"); // 秘密鍵
        byte[] S = Bin.toByteArray("DC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1"); // s2 署名2
        byte[] Qx = Bin.toByteArray("B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19"); // 公開鍵
        byte[] Qy = Bin.toByteArray("3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09"); // 公開鍵

        ECCurvep P256 = EllipticCurve.P256;
        ECDSAPrivateKey pk = new ECDSAPrivateKey(P256, D); // 秘密鍵
        BigInteger q = P256.getN();

        BigInteger k = PKCS1.OS2IP(K).mod(q); // 乱数
        BigInteger kinv = k.modInverse(q);
//        System.out.println("Kinv:" +kinv.toString(16));
        assertArrayEquals(Kinv, PKCS1.I2OSP(kinv, Kinv.length));
        ECCurvep.ECPointp R_ = P256.xG(k);
//        System.out.println("Rx:" + R_.getX().toString(16));
        assertArrayEquals(Rx, R_.encX());
//        System.out.println("Ry:" + R_.getY().toString(16));
        assertArrayEquals(Ry, R_.encY());
//        System.out.println(EllipticCurve.P256.xG(k).getX().toString(16));
//        System.out.println("Ry:" + R_.getY().toString(16));
        BigInteger e = PKCS1.OS2IP(E);
        BigInteger r = R_.getX().mod(q);
//        System.out.println("R:" + r.toString(16));
        assertEquals(PKCS1.OS2IP(R), r);
        int blen = ((P256.n.bitLength()) + 7) / 8;
        byte[] RR = PKCS1.I2OSP(r, blen);
        assertArrayEquals(R, RR);
        BigInteger d = pk.getS(); // 秘密鍵
        BigInteger s2a = e.add(d.multiply(r).mod(q)).mod(q);
        System.out.println(s2a.toString(16));
        BigInteger s = e.add(d.multiply(r)).mod(q).multiply(kinv).mod(q);
        System.out.println(s.toString(16));
        assertEquals(PKCS1.OS2IP(S), s);
        byte[] SS = PKCS1.I2OSP(s, blen);
        assertArrayEquals(S, SS);

        // ( r ,s )
        byte[] RS = new byte[blen * 2];
        System.arraycopy(RR, 0, RS, 0, blen);
        System.arraycopy(SS, 0, RS, blen, blen);

        ECDSA ec = new ECDSA(pk, new SHA256());
        byte[] sign = ec.sign(E, k);
        System.out.println();
        assertArrayEquals(RS, sign);

        // verify
        BigInteger s2inv = s.modInverse(q);
        System.out.println(s2inv.toString(16));
        BigInteger u1 = e.multiply(s2inv).mod(q);
        System.out.println("u1:" + u1.toString(16));
        BigInteger u2 = r.multiply(s2inv).mod(q);
        System.out.println("u2:" + u2.toString(16));

        ECCurvep.ECPointp Q = (ECCurvep.ECPointp) pk.getPublicKey().getY();
//        System.out.println("Qx:" + Bin.toUpperHex(Qx));
//        System.out.println("Qx:" + Q.getX().toString(16));
//        System.out.println("Qy:" + Q.getY().toString(16));
        assertArrayEquals(Qx, Q.encX());
        assertArrayEquals(Qy, Q.encY());

//        assertEquals(PKCS1.OS2IP(S),s);
        ECCurvep.ECPoint VR = P256.xG(u1).add(Q.x(u2));
        assertEquals(VR.getX(), r);
    }

    /**
     * Curve: B-283 Hash Algorithm: SHA3-256
     */
    @Test
    public void testVectorB283() {
        System.out.println("Vector B-283 SHA3-256");
//        byte[] d  = Bin.toByteArray("e5ce89a34adddf25ff3bf1ffe6803f57d0220de3118798ea");
        String msg = "Example of ECDSA with B-283";
        byte[] H    = Bin.toByteArray("B4809C0A000C5290B65D26DF9F12ADD919588FD4468958BC67CC7D9950A27EB8"); // Hash(M)
        byte[] E    = Bin.toByteArray("B4809C0A000C5290B65D26DF9F12ADD919588FD4468958BC67CC7D9950A27EB8"); // 切り詰めた値
        byte[] K    = Bin.toByteArray("0100EC321393E6DD6C4D47BE5AE189E5E35408579D0862178F94CCBBA3C4049A4D88E297"); // 乱数? どめいんぱらめーた? 乱数
        byte[] Kinv = Bin.toByteArray("AB6D18AF222D8FDE7D93894D4FAEEB36ACCD4FB68EC95D9E9BFF4C08AFF3C631A67BE4"); // inv n GF2^mはつかわない
        byte[] Rx   = Bin.toByteArray("077CB284AC41E72EDA2A93EB8D6DFF58620F6C69D528DFE90D909AA5CABC03A34E5D5A76"); // 公開鍵 R Q
        byte[] Ry   = Bin.toByteArray("0289997A39B5287D0905D9C4AF94EFEA4B9A1A7E7B983FDDC909E8ACF56EED7F97D7E1C0");
        byte[] R    = Bin.toByteArray("037CB284AC41E72EDA2A93EB8D6DFF58620F7CD99B927EEC7A060A8F6FB7D9265EAFA76F"); // r 署名1
        byte[] D    = Bin.toByteArray("010652D37B0A9DB64D4033AC6549CD1DF37E1EEDE2612C2363257C6AFF6C8CB5DCB63648"); // 秘密鍵
        byte[] S    = Bin.toByteArray("027A943BE3894A44E3EAA2A90CD83883767DBA364A10643BDECBE65C104AE104589BED7A"); // s2 署名2

        byte[] Qx = Bin.toByteArray("0390858E9327A714C74AF0C3ADEDF4E6C75CAFDCC46507A49E415B138A094B6F43E882AC"); // 公開鍵
        byte[] Qy = Bin.toByteArray("D4A65D973CD150A5221BEDF872A4BA207FF4427DFFFD4827C5BF169E719162504D0631"); // 公開鍵
        byte[] Sinv = Bin.toByteArray("93B6AC351661E86BBC76029EBA8EBD9B65909AFE1C21BB2A50FFF3AC0C806273514169");

        SHA3 sha = new SHA3256();
        sha.update(msg.getBytes(StandardCharsets.UTF_8));
        byte[] oH = sha.digest();
        assertArrayEquals(H, oH);

        ECCurvet B283 = EllipticCurve.B283;
        System.out.println("p:" + B283.p.toString(16));
        ECDSAPrivateKey pk = new ECDSAPrivateKey(B283, D); // 秘密鍵
        BigInteger q = B283.getN();

        System.out.println("n:" + B283.p.bitLength());
        BigInteger k = PKCS1.OS2IP(K).mod(B283.getP()); // 乱数
        //k = BigInteger.valueOf(3);

        BIGF gf = new BIGF(B283.getP());
        BigInteger kinvgf = gf.inv(k);
        BigInteger zk = gf.mul(kinvgf, k);
        BigInteger kinv = k.modInverse(q);
        System.out.println("Kinv:" + Bin.toHex(Kinv));
        BigInteger kinv2 = k.modInverse(B283.p);
//        GFL gf = new GFL(B283.getN());
        System.out.println("K:" + Bin.toHex(K));
        System.out.println("K:" + k.toString(16));

        //BigInteger kinv = PKCS1.OS2IP(Bin.ltob(gf.inv(GFL.toLong(K))));
        System.out.println("zK  :" + zk.toString(16));
        System.out.println("zKK :" + gf.mul(zk, k).toString(16));
        System.out.println("Kinv:" + kinv.toString(16));
        System.out.println("Kinv2:" + kinv2.toString(16));
        System.out.println("KinvGF:" + kinvgf.toString(16));
        
        assertArrayEquals(Kinv, PKCS1.I2OSP(kinv, Kinv.length));
        ECCurvet.ECPointt R_ = B283.xG(k);

        gf = new BIGF(B283.getP());
        k = BigInteger.valueOf(3);
        zk = gf.inv(k);
        System.out.println("zk:" + zk.toString(16));
        BigInteger kk = gf.mul(zk, k);
        System.out.println("kk:" + kk.toString(16));

        BigInteger x = R_.getX();
        BigInteger y = R_.getY();
        System.out.println("Rx:" + x.toString(16));
//        System.out.println("Rx:" + Bin.toHex(Rx));
        System.out.println("Ry:" + y.toString(16));
//        System.out.println("Ry:" + Bin.toHex(Ry));
        assertArrayEquals(Rx, R_.encX());
        assertArrayEquals(Ry, R_.encY());
        BigInteger e = PKCS1.OS2IP(E);
        BigInteger r = R_.getX().mod(q);
        assertEquals(PKCS1.OS2IP(R),r);
        int blen = (B283.getN().bitLength() + 7) / 8;
        byte[] RR = PKCS1.I2OSP(r, blen);
        assertArrayEquals(R,RR);
        BigInteger d = pk.getS(); // 秘密鍵
        BigInteger s2a = e.add(d.multiply(r).mod(q)).mod(q);
        System.out.println(s2a.toString(16));
        BigInteger s = e.add(d.multiply(r)).mod(q).multiply(kinv).mod(q);
        System.out.println(s.toString(16));
        assertEquals(PKCS1.OS2IP(S),s);
        byte[] SS = PKCS1.I2OSP(s, blen);
        assertArrayEquals(S,SS);

        // ( r ,s )
        byte[] RS = new byte[blen*2];
        System.arraycopy(RR, 0, RS, 0, blen);
        System.arraycopy(SS, 0, RS, blen, blen);
/*        
        ECDSA ec = new ECDSA(pk, new SHA3256());
        byte[] sign = ec.sign(E, k);
        System.out.println("RS  :" + Bin.toHex(RS));
        System.out.println("sign:" + Bin.toHex(sign));
        assertArrayEquals(RS,sign);
*/
    }

    /*
        
        
        // verify
        BigInteger s2inv = s.modInverse(q);
        System.out.println(s2inv.toString(16));
        BigInteger u1 = e.multiply(s2inv).mod(q);
        System.out.println("u1:"+u1.toString(16));
        BigInteger u2 = r.multiply(s2inv).mod(q);
        System.out.println("u2:"+u2.toString(16));

        ECCurvet.ECPointt Q = (ECCurvet.ECPointt) pk.getPublicKey().getY();
//        System.out.println("Qx:" + Bin.toUpperHex(Qx));
//        System.out.println("Qx:" + Q.getX().toString(16));
//        System.out.println("Qy:" + Q.getY().toString(16));
        assertArrayEquals(Qx,Q.encX());
        assertArrayEquals(Qy,Q.encY());

//        assertEquals(PKCS1.OS2IP(S),s);
        ECCurvet.ECPoint VR = B283.xG(u1).add(Q.x(u2));
        assertEquals(VR.getX(),r);
    }
     */

    @Test
    public void testVectorK163() {
        System.out.println("EC K-163");
        byte[] N = Bin.toByteArray("0004000000000000000000020108A2E0CC0D99F8A5EF");
    }

    @Test
    public void testVectorK233() {
        System.out.println("EC K-233");
        ECCurvet K233 = EllipticCurve.K233;
        SHA3224 sha = new SHA3224();
        byte[] src = "Example of ECDSA with K-233".getBytes(StandardCharsets.ISO_8859_1);
        byte[] H = Bin.toByteArray("82002E97C4A760B35EEE9059D533B5F25EF3D736D78839C0398FAFAB");
        byte[] rH = sha.digest(src);
        assertArrayEquals(H,rH);
        byte[] N = Bin.toByteArray("0004000000000000000000020108A2E0CC0D99F8A5EF");
        byte[] K = Bin.toByteArray("0190DA60FE3B179B96611DB7C7E5217C9AFF0AEE435782EBFB2DFFF27F");
        byte[] Kinv = Bin.toByteArray("759A37371C026E261ADD7278B81EE15D18E2B0D9BD1A077AEBF96AA067");
        BigInteger p = K233.getP();
        BigInteger n = K233.getN();
        BIGF gf = new BIGF(p);
        
        BigInteger k = new BigInteger(K);
        BigInteger rKinv = gf.inv(new BigInteger(K));
        System.out.println("K " + gf.pow(BigInteger.TWO, n).toString(16));
        System.out.println("Kinv " + rKinv.toString(16));
        assertEquals(new BigInteger(Kinv), k.modInverse(n));
        
    }

    @Test
    public void testVectorB409() {
        System.out.println("VectorB409");
//        byte[] d  = Bin.toByteArray("e5ce89a34adddf25ff3bf1ffe6803f57d0220de3118798ea");
        byte[] H  = Bin.toByteArray("4BBF1BC0DDF9D3B7BFE21FC68642B3E5508CA6BA4D365C1D00ABBFABDB0F3EC2B0BE995AE803DE47D0880BF192649EDC"); // Hash(M)
        byte[] E  = Bin.toByteArray("4BBF1BC0DDF9D3B7BFE21FC68642B3E5508CA6BA4D365C1D00ABBFABDB0F3EC2B0BE995AE803DE47D0880BF192649EDC"); // 切り詰めた値
        byte[] K  = Bin.toByteArray("6A0B81D9320B5C305D730B1C1E74B03FAFB88A7EC355990B75F9B70E8532433296A32492CBA06F8583D5B19C5B8C5D6D07EC"); // 乱数? どめいんぱらめーた? 乱数
        byte[] Kinv=Bin.toByteArray("A202EA455D0E1A5EF09054B39259C768DB76FFD1A77B6281FC7056A4A23A1012CDD604E4D7993E0D9EDD422DEFD782C1225A1A"); // inv n
        byte[] Rx = Bin.toByteArray("01F3E4DA3101C64239D76831995C0EC1E56CE4690C42DDD53DBF3EF725D819DF090B8632F327499B5B99C280D7F410CD7105C8DB"); // 公開鍵 R Q
        byte[] Ry = Bin.toByteArray("0122C8D8E5BEEC67621FF662D16D96845ADD77930A1096913CFFC984E97DA8E7351F73AC33BEAD2C2FA5B3049FC53FCF38160AF5");
        byte[] R  = Bin.toByteArray("F3E4DA3101C64239D76831995C0EC1E56CE4690C42DDD53DBF3D147B0173CC15D87E749382CD5EBD9492FD568F43959763B768"); // r 署名1
        byte[] D  = Bin.toByteArray("4AF896DB379ABDF70C8FADE9EBD28CD530F2ECB336B4DE84BD6E065EF56C8C548C532D00FA55CA8ACF3E98ADBCA9F78D241B"); // 秘密鍵
        byte[] S  = Bin.toByteArray("292FA994DC6EA367236AD73956DBC1EB62B8779DF438165407141587E3FEED883741CDF5542F255BEBC57B9D0C87AD403B8EAB"); // s2 署名2

        byte[] Qx = Bin.toByteArray("01951C5E41607E9317F247D49A389D0E120F479D47737543098AE5E1BB62BD59DE70E1C584AE655C702D39DD4F7883E1876C4A9B"); // 公開鍵
        byte[] Qy = Bin.toByteArray("016B16B98A3353D75BEB4D3576C64568BA381463CF77D4AEB85218D2D546E7A1EE3AB9316D8C7DF00D155B7891B2C0BF4B5E942E"); // 公開鍵
        byte[] Sinv=Bin.toByteArray("19BAA800F6AD546E7E5D45F702C68BB4D4845C839B3D75AED776E7C8A9D17D8EB41BD50FC7B707B49D10758977BD9472E7E998");

        ECCurvet B409 = EllipticCurve.B409;
        ECDSAPrivateKey pk = new ECDSAPrivateKey(B409, D); // 秘密鍵
        BigInteger q = B409.getN();

        System.out.println("n;" + B409.b.bitLength());
        BigInteger k = PKCS1.OS2IP(K).mod(q); // 乱数
        BigInteger kinv = k.modInverse(q);
        BIGF gf = new BIGF(B409.getN());
        System.out.println("K:" +Bin.toHex(K));
        System.out.println("K:" +k.toString(16));
        byte[] bkinv = PKCS1.I2OSP(kinv, Kinv.length);
        System.out.println("Kinvlen:" + Kinv.length);
        System.out.println("Kinv:" +Bin.toHex(Kinv));
//        System.out.println("Kinv:" +Bin.toHex(bkinv));
//        System.out.println("Kinv:" +kinv.toString(16));
        System.out.println("Kinv:" +kinv.toString(16));
        assertArrayEquals(Kinv, bkinv);
        ECCurvep.ECPoint R_ = B409.xG(k);
//        System.out.println("Rx:" + R_.getX().toString(16));
        assertArrayEquals(Rx,R_.encX());
//        System.out.println("Ry:" + R_.getY().toString(16));
        assertArrayEquals(Ry,R_.encY());
//        System.out.println(EllipticCurve.P256.xG(k).getX().toString(16));
//        System.out.println("Ry:" + R_.getY().toString(16));
        BigInteger e = PKCS1.OS2IP(E);
        BigInteger r = R_.getX().mod(q);
//        System.out.println("R:" + r.toString(16));
        assertEquals(PKCS1.OS2IP(R),r);
        int blen = (B409.getN().bitLength() + 7) / 8;
        byte[] RR = PKCS1.I2OSP(r, blen);
/*
        assertArrayEquals(R,RR);
        BigInteger d = pk.getS(); // 秘密鍵
        BigInteger s2a = e.add(d.multiply(r).mod(q)).mod(q);
        System.out.println(s2a.toString(16));
        BigInteger s = e.add(d.multiply(r)).mod(q).multiply(kinv).mod(q);
        System.out.println(s.toString(16));
        assertEquals(PKCS1.OS2IP(S),s);
        byte[] SS = PKCS1.I2OSP(s, blen);
        assertArrayEquals(S,SS);
        
        // ( r ,s )
        byte[] RS = new byte[blen*2];
        System.arraycopy(RR, 0, RS, 0, blen);
        System.arraycopy(SS, 0, RS, blen, blen);
        
        ECDSA ec = new ECDSA(pk, new SHA256());
        byte[] sign = ec.sign(E, k);
        System.out.println();
        assertArrayEquals(RS,sign);
        
        // verify
        BigInteger s2inv = s.modInverse(q);
        System.out.println(s2inv.toString(16));
        BigInteger u1 = e.multiply(s2inv).mod(q);
        System.out.println("u1:"+u1.toString(16));
        BigInteger u2 = r.multiply(s2inv).mod(q);
        System.out.println("u2:"+u2.toString(16));

        ECCurvet.ECPointt Q = (ECCurvet.ECPointt) pk.getPublicKey().getY();
//        System.out.println("Qx:" + Bin.toUpperHex(Qx));
//        System.out.println("Qx:" + Q.getX().toString(16));
//        System.out.println("Qy:" + Q.getY().toString(16));
        assertArrayEquals(Qx,Q.encX());
        assertArrayEquals(Qy,Q.encY());

//        assertEquals(PKCS1.OS2IP(S),s);
        ECCurvet.ECPoint VR = B409.xG(u1).add(Q.x(u2));
        assertEquals(VR.getX(),r);
*/
    }

    /**
     * Test of toECDSAKey method, of class ECDSA.
     */
    @Test
    public void testToECDSAKey_ECPublicKey() {
        System.out.println("toECDSAKey");
        ECDSAPrivateKey prv = new ECDSAKeyGen().genPrivateKey(EllipticCurve.P256);
        ECPublicKey pub = prv.getPublicKey();
        ECDSAPublicKey expResult = prv.getPublicKey();
        ECDSAPublicKey result = ECDSA.toECDSAKey(pub);
//        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of getKeyLength method, of class ECDSA.
     */
    @Test
    public void testGetKeyLength() {
        System.out.println("getKeyLength");
        ECDSAPrivateKey key = new ECDSAKeyGen().genPrivateKey(EllipticCurve.P256);
        ECDSA instance = new ECDSA(key, new SHA256());
        int expResult = 256 / 8;
        int result = instance.getKeyLength();
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    @Test
    public void testSecp256k1() {
        System.out.println("Secp256k1");
        byte[] k = Bin.toByteArray("01");
        ECCurvep p256k1 = EllipticCurve.secp256k1;
        ECCurvep.ECPointp P = p256k1.xG(BigInteger.ONE);
        System.out.println(P.getX().toString(16));
        P = p256k1.xG(BigInteger.valueOf(2));
        System.out.println(P.getX().toString(16));
    }

    /**
     * Test of update,sign method, of class ECDSA.
     */
    @Test
    public void testSign() {
        System.out.println("update,sign");
        ECDSAPrivateKey key = new ECDSAKeyGen().genPrivateKey(EllipticCurve.P256);
        ECDSA instance = new ECDSA(key, new SHA256());
        byte[] expResult = new byte[10];
        byte[] src = new byte[10];
        int offset = 0;
        int length = 1;
        instance.update(src, offset, length);
        byte[] result = instance.sign();
//        assertArrayEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

    /**
     * Test of verify method, of class ECDSA.
     */
    @Test
    public void testVerify() {
        System.out.println("verify");
        byte[] sign = Bin.toByteArray("0000");
        ECDSAPrivateKey key = new ECDSAKeyGen().genPrivateKey(EllipticCurve.P256);
        ECDSAPublicKey pub = key.getPublicKey();
        ECDSA instance = new ECDSA(pub, new SHA256());
        boolean expResult = false;
        byte[] src = new byte[10];
        instance.update(src);
        boolean result = instance.verify(sign);
        assertEquals(expResult, result);
        // TODO review the generated test code and remove the default call to fail.
//        fail("The test case is a prototype.");
    }

}
