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
package net.siisise.security.key;

import java.math.BigInteger;
import net.siisise.lang.Bin;
import net.siisise.security.ec.Curve;
import net.siisise.security.ec.Curve25519;
import net.siisise.security.ec.Curve448;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 * RFC 7748
 */
public class ECDHTest {
    
    public ECDHTest() {
    }

    /**
     * 5.2
     */
    @Test
    public void testX255191() {
        System.out.println("ECDH X25519 1");
        byte[] scalar = Bin.toByteArray("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
        byte[] u      = Bin.toByteArray("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
        byte[] exOut  = Bin.toByteArray("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
        Curve c = new Curve25519();
        BigInteger gu = BigInteger.valueOf(9);
        BigInteger v = c.v(gu).getY();
        System.out.println("v:" + v.toString());
        scalar = c.cutk(scalar);
        System.out.println(Bin.lbtobi(scalar));
        System.out.println(Bin.lbtobi(u));
        byte[] k = scalar;
        //u = c.cuts(Pu);
        byte[] out = c.x(k, u);
        assertArrayEquals(exOut, out);
    }

    @Test
    public void testX255192() {
        System.out.println("ECDH X25519 2");
        byte[] scalar = Bin.toByteArray("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
        byte[] u      = Bin.toByteArray("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
        byte[] exOut  = Bin.toByteArray("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
        Curve c = new Curve25519();
        scalar = c.cutk(scalar);
       // Pu = c.cuts(Pu);
        byte[] out = c.x(scalar, u);
        assertArrayEquals(exOut, out);
    }   

    @Test
    public void testX4481() {
        System.out.println("ECDH X448 1");
        byte[] scalar = Bin.toByteArray("3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3");
        byte[] u      = Bin.toByteArray("06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086");
        byte[] exOut  = Bin.toByteArray("ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f");
        Curve c = new Curve448();
        BigInteger v = c.v(new BigInteger(c.Pu)).getY();
        System.out.println("v:" + v.toString());
        scalar = c.cutk(scalar);
        System.out.println(Bin.lbtobi(scalar));
        System.out.println(Bin.lbtobi(u));
        byte[] k = scalar;
        //u = c.cuts(Pu);
        byte[] out = c.x(k, u);
        assertArrayEquals(exOut, out);
    }

    @Test
    public void testX4482() {
        System.out.println("ECDH X448 2");
        byte[] scalar = Bin.toByteArray("203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f");
        byte[] u      = Bin.toByteArray("0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db");
        byte[] exOut  = Bin.toByteArray("884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d");
        Curve c = new Curve448();
        scalar = c.cutk(scalar);
        System.out.println(Bin.lbtobi(scalar));
        System.out.println(Bin.lbtobi(u));
        //u = c.cuts(Pu);
        byte[] out = c.x(scalar, u);
        assertArrayEquals(exOut, out);
    }

    @Test
    public void testCurve25519() {
        System.out.println("ECDH 6.1 Curve25519");
        byte[] a      = Bin.toByteArray("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] apubEx = Bin.toByteArray("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
        System.out.println("a:"  + Bin.toHex(a));
        Curve c = new Curve25519();
        byte[] ak = c.cutk(a);
        byte[] bapub = c.x(ak, c.Pu);
        assertArrayEquals(apubEx, bapub);

        byte[] b      = Bin.toByteArray("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        byte[] bpubEx = Bin.toByteArray("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
        System.out.println("b:"  + Bin.toHex(b));
        byte[] bk = c.cutk(b);
        byte[] bbpub = c.x(bk, c.Pu);
        assertArrayEquals(bpubEx, bbpub);

        byte[] ac = c.x(bk, bapub);
        byte[] bc = c.x(ak, bbpub);
        assertArrayEquals(ac,bc);
        byte[] exCc = Bin.toByteArray("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assertArrayEquals(exCc,ac);
    }

    @Test
    public void testCurve448() {
        System.out.println("ECDH 6.2 Curve448");
        byte[] a      = Bin.toByteArray("9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b");
        byte[] apubEx = Bin.toByteArray("9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0");
        System.out.println("a:"  + Bin.toHex(a));
        Curve c = new Curve448();
        byte[] ak = c.cutk(a);
        byte[] bapub = c.x(ak, c.Pu);
        assertArrayEquals(apubEx, bapub);

        System.out.println("b:::");
        byte[] b      = Bin.toByteArray("1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d");
        byte[] bpubEx = Bin.toByteArray("3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609");
        byte[] bk = c.cutk(b);
        byte[] bbpub = c.x(bk, c.Pu);
        assertArrayEquals(bpubEx, bbpub);

        byte[] ac = c.x(bk, bapub);
        byte[] bc = c.x(ak, bbpub);
        assertArrayEquals(ac,bc);
        byte[] exCc = Bin.toByteArray("07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d");
        assertArrayEquals(exCc,ac);
    }
}
