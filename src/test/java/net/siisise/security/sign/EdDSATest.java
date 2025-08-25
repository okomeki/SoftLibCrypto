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

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.EdECPrivateKey;
import java.security.spec.EdECPrivateKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.NamedParameterSpec;
import net.siisise.iso.asn1.ASN1Util;
import net.siisise.iso.asn1.tag.OCTETSTRING;
import net.siisise.lang.Bin;
import net.siisise.security.digest.SHAKE256;
import net.siisise.security.key.EdDSAPrivateKey;
import net.siisise.security.key.EdDSAPublicKey;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class EdDSATest {
    
    public EdDSATest() {
    }

    /**
     * Test of init25519 method, of class EdDSA.
     */
    @Test
    public void testInit25519() {
        System.out.println("init25519");
        EdDSA instance = new EdDSA();
        instance.init25519();
    }

    /**
     * Test of init448 method, of class EdDSA.
     */
    @Test
    public void testInit448() {
        System.out.println("init448");
        EdDSA instance = new EdDSA();
        instance.init448();
    }

    /**
     * Test of getKeyLength method, of class EdDSA.
     */
    @Test
    public void testGetKeyLength() {
        System.out.println("getKeyLength");
        EdDSA instance = new EdDSA();
        instance.genPrvKey(new EdDSA.EdWards25519());
        int expResult = 256/8;
        int result = instance.getKeyLength();
        assertEquals(expResult, result);
    }

    /**
     * Test of update method, of class EdDSA.
     */
    @Test
    public void testUpdate() {
        System.out.println("update");
        byte[] src = null;
        int offset = 0;
        int length = 0;
        EdDSA instance = new EdDSA();
        instance.init25519();
        instance.update(src, offset, length);
    }

    /**
     * Test of genPrvKey method, of class EdDSA.
     */
    @Test
    public void testGenPrvKey() {
        System.out.println("genPrvKey");
        EdDSA instance = new EdDSA();
        EdDSA.EdWards25519 curve = instance.init25519();
        int expResult = 32;
        byte[] result = instance.genPrvKey(curve);
        OCTETSTRING oct = (OCTETSTRING) ASN1Util.toASN1(result);
        
        assertEquals(expResult, oct.getValue().length);
    }

    class Ptn {
        byte[] key;
        byte[] pub;
        byte[] msg;
        byte[] sig;
        
        Ptn(byte[] k, byte[] p, byte[] m, byte[] s) {
            key = k;
            pub = p;
            msg = m;
            sig = s;
        }
    }

    void GenPubKey(EdDSA.EdWards ed, Ptn ptn) {
        System.out.println(" GenPubKey:");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(ed, ptn.key);
        EdDSA instance = new EdDSA(pkey);
        System.out.println("s:" + pkey.gets());
        byte[] result = instance.genPubKey();
        EdDSAPublicKey pub = new EdDSAPublicKey(ed, result);
//        System.out.println(pub.);
        System.out.println("PA:" + Bin.toHex(pub.getA()));
        assertArrayEquals(ptn.pub, result);
    }
    
    void Sign(EdDSA.EdWards ed, Ptn ptn) {
        System.out.println(" Sign:");
        EdDSAPrivateKey pkey = new EdDSAPrivateKey(ed, ptn.key);
        EdDSA instance = new EdDSA(pkey);
        instance.update(ptn.msg);
        byte[] result = instance.sign();
        System.out.println(Bin.toHex(ptn.sig));
        System.out.println(Bin.toHex(result));
        assertArrayEquals(ptn.sig, result);
    }
    
    void Verify(EdDSA.EdWards ed, Ptn ptn) {
        System.out.println(" Verify");
        EdDSAPublicKey pubKey = new EdDSAPublicKey(ed, ptn.pub);
        EdDSA instance = new EdDSA(pubKey);
        instance.update(ptn.msg);
        boolean expResult = true;
        boolean result = instance.verify(ptn.sig);
        assertEquals(expResult, result);
    }
    
    void tall(EdDSA.EdWards ed, Ptn ptn) {
        GenPubKey(ed, ptn);
        Sign(ed, ptn);
        Verify(ed, ptn);
    }
    
    static byte[] KEY1 = Bin.toByteArray("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    static byte[] PUB1 = Bin.toByteArray("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    static byte[] SIG1 = Bin.toByteArray("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey255191() {
        System.out.println("genPubKey25519 1");
        EdDSA.EdWards ed = new EdDSA.EdWards25519();
        Ptn ptn = new Ptn(KEY1, PUB1, new byte[0], SIG1);
        tall(ed, ptn);
    }

    static byte[] KEY2 = Bin.toByteArray("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
    static byte[] PUB2 = Bin.toByteArray("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
    static byte[] MSG2 = Bin.toByteArray("72");
    static byte[] SIG2 = Bin.toByteArray("92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey255192() {
        System.out.println("genPubKey25519 2");
        EdDSA.EdWards ed = new EdDSA.EdWards25519();
        Ptn ptn = new Ptn(KEY2, PUB2, MSG2, SIG2);
        tall(ed, ptn);
    }

    static byte[] KEY3 = Bin.toByteArray("c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
    static byte[] PUB3 = Bin.toByteArray("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
    static byte[] MSG3 = Bin.toByteArray("af82");
    static byte[] SIG3 = Bin.toByteArray("6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey255193() {
        System.out.println("genPubKey25519 3");
        EdDSA.EdWards ed = new EdDSA.EdWards25519();
        Ptn ptn = new Ptn(KEY3, PUB3, MSG3, SIG3);
        tall(ed, ptn);
    }

    static byte[] KEY4 = Bin.toByteArray("f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5");
    static byte[] PUB4 = Bin.toByteArray("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
    static byte[] MSG4 = Bin.toByteArray("08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98" +
"fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8" +
"79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d" +
"658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc" +
"1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4fe" +
"ba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e" +
"06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbef" +
"efd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7" +
"aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed1" +
"85ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2" +
"d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24" +
"554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270" +
"88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc" +
"2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07" +
"07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128ba" +
"b27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a" +
"ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429e" +
"c96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7" +
"51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c" +
"42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8" +
"ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34df" +
"f7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08" +
"d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649" +
"de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4" +
"88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a3" +
"2ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e" +
"6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5f" +
"b93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5" +
"0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1" +
"369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d" +
"b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c" +
"0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0");
    static byte[] SIG4 = Bin.toByteArray("0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350" +
"aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03");

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey255194() {
        System.out.println("genPubKey25519 4");
        EdDSA.EdWards ed = new EdDSA.EdWards25519();
        Ptn ptn = new Ptn(KEY4, PUB4, MSG4, SIG4);
        tall(ed, ptn);
    }

    static byte[] KEY5 = Bin.toByteArray("833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42");
    static byte[] PUB5 = Bin.toByteArray("ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf");
    static byte[] MSG5 = Bin.toByteArray("ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
    static byte[] SIG5 = Bin.toByteArray("dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704");

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey255195() {
        System.out.println("genPubKey25519 5");
        EdDSA.EdWards ed = new EdDSA.EdWards25519();
        Ptn ptn = new Ptn(KEY5, PUB5, MSG5, SIG5);
        tall(ed, ptn);
    }

    static byte[] KEY4481 = Bin.toByteArray("6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b");
    static byte[] PUB4481 = Bin.toByteArray("5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180");
    static byte[] SIG4481 = Bin.toByteArray("533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600");

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey4481() {
        System.out.println("genPubKey448 1 -----Blank");
        EdDSA.EdWards ed = new EdDSA.EdWards448();
        Ptn ptn = new Ptn(KEY4481, PUB4481, new byte[0], SIG4481);
        tall(ed, ptn);
    }

    static byte[] KEY4482 = Bin.toByteArray("c4eab05d357007c632f3dbb48489924d552b08fe0c353a0d4a1f00acda2c463afbea67c5e8d2877c5e3bc397a659949ef8021e954e0a12274e");
    static byte[] PUB4482 = Bin.toByteArray("43ba28f430cdff456ae531545f7ecd0ac834a55d9358c0372bfa0c6c6798c0866aea01eb00742802b8438ea4cb82169c235160627b4c3a9480");
    static byte[] MSG4482 = Bin.toByteArray("03");
    static byte[] SIG4482 = Bin.toByteArray("26b8f91727bd62897af15e41eb43c377efb9c610d48f2335cb0bd0087810f4352541b143c4b981b7e18f62de8ccdf633fc1bf037ab7cd779805e0dbcc0aae1cbcee1afb2e027df36bc04dcecbf154336c19f0af7e0a6472905e799f1953d2a0ff3348ab21aa4adafd1d234441cf807c03a00");
//    static byte[] SIG4483 = Bin.toByteArray("d4f8f6131770dd46f40867d6fd5d5055de43541f8c5e35abbcd001b32a89f7d2151f7647f11d8ca2ae279fb842d607217fce6e042f6815ea000c85741de5c8da1144a6a1aba7f96de42505d7a7298524fda538fccbbb754f578c1cad10d54d0d5428407e85dcbc98a49155c13764e66c3c00");
    
    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey4482() {
        System.out.println("genPubKey448 2 -----1 octet");
        EdDSA.EdWards ed = new EdDSA.EdWards448();
        Ptn ptn = new Ptn(KEY4482, PUB4482, MSG4482, SIG4482);
        tall(ed, ptn);
    }
    static byte[] KEY4484 = Bin.toByteArray("cd23d24f714274e744343237b93290f511f6425f98e64459ff203e8985083ffdf60500553abc0e05cd02184bdb89c4ccd67e187951267eb328");
    static byte[] PUB4484 = Bin.toByteArray("dcea9e78f35a1bf3499a831b10b86c90aac01cd84b67a0109b55a36e9328b1e365fce161d71ce7131a543ea4cb5f7e9f1d8b00696447001400");
    static byte[] MSG4484 = Bin.toByteArray("0c3e544074ec63b0265e0c");
    static byte[] SIG4484 = Bin.toByteArray("1f0a8888ce25e8d458a21130879b840a9089d999aaba039eaf3e3afa090a09d389dba82c4ff2ae8ac5cdfb7c55e94d5d961a29fe0109941e00b8dbdeea6d3b051068df7254c0cdc129cbe62db2dc957dbb47b51fd3f213fb8698f064774250a5028961c9bf8ffd973fe5d5c206492b140e00");

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey4484() {
        System.out.println("genPubKey448 4 11 octets");
        EdDSA.EdWards ed = new EdDSA.EdWards448();
        Ptn ptn = new Ptn(KEY4484, PUB4484, MSG4484, SIG4484);
        tall(ed, ptn);
    }

    static byte[] KEY4485 = Bin.toByteArray("258cdd4ada32ed9c9ff54e63756ae582fb8fab2ac721f2c8e676a72768513d939f63dddb55609133f29adf86ec9929dccb52c1c5fd2ff7e21b");
    static byte[] PUB4485 = Bin.toByteArray("3ba16da0c6f2cc1f30187740756f5e798d6bc5fc015d7c63cc9510ee3fd44adc24d8e968b6e46e6f94d19b945361726bd75e149ef09817f580");
    static byte[] MSG4485 = Bin.toByteArray("64a65f3cdedcdd66811e2915");
    static byte[] SIG4485 = Bin.toByteArray("7eeeab7c4e50fb799b418ee5e3197ff6bf15d43a14c34389b59dd1a7b1b85b4ae90438aca634bea45e3a2695f1270f07fdcdf7c62b8efeaf00b45c2c96ba457eb1a8bf075a3db28e5c24f6b923ed4ad747c3c9e03c7079efb87cb110d3a99861e72003cbae6d6b8b827e4e6c143064ff3c00");

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey4485() {
        System.out.println("genPubKey448 5 12 octet");
        EdDSA.EdWards ed = new EdDSA.EdWards448();
        Ptn ptn = new Ptn(KEY4485, PUB4485, MSG4485, SIG4485);
        tall(ed, ptn);
    }

    static byte[] KEY4486 = Bin.toByteArray("7ef4e84544236752fbb56b8f31a23a10e42814f5f55ca037cdcc11c64c9a3b2949c1bb60700314611732a6c2fea98eebc0266a11a93970100e");
    static byte[] PUB4486 = Bin.toByteArray("b3da079b0aa493a5772029f0467baebee5a8112d9d3a22532361da294f7bb3815c5dc59e176b4d9f381ca0938e13c6c07b174be65dfa578e80");
    static byte[] MSG4486 = Bin.toByteArray("64a65f3cdedcdd66811e2915e7");
    static byte[] SIG4486 = Bin.toByteArray("6a12066f55331b6c22acd5d5bfc5d71228fbda80ae8dec26bdd306743c5027cb4890810c162c027468675ecf645a83176c0d7323a2ccde2d80efe5a1268e8aca1d6fbc194d3f77c44986eb4ab4177919ad8bec33eb47bbb5fc6e28196fd1caf56b4e7e0ba5519234d047155ac727a1053100");

    /**
     * Test of genPubKey method, of class EdDSA.
     */
    @Test
    public void testKey4486() {
        System.out.println("genPubKey448 6 13 octet");
        EdDSA.EdWards ed = new EdDSA.EdWards448();
        Ptn ptn = new Ptn(KEY4486, PUB4486, MSG4486, SIG4486);
        tall(ed, ptn);
    }
}
