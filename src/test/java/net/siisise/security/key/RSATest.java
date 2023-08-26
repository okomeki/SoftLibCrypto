/*
 * Copyright 2023 okome.
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
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class RSATest {

    public RSATest() {
    }

    /**
     * Test of generatePrivateKey method, of class RSA.
     */
    @Test
    public void testCreatePrivateKey() throws Exception {
        System.out.println("createPrivateKey");
        int len = 2049;
        RSAPrivateCrtKey expResult = null;
        RSAPrivateCrtKey key = RSAKeyGen.generatePrivateKey(len);
//        assertEquals(expResult, key);
        // TODO review the generated test code and remove the default call to fail.
        BigInteger p1e = key.prime1.subtract(BigInteger.ONE);
        BigInteger p2e = key.prime2.subtract(BigInteger.ONE);
//        assertEquals(key.publicExponent.modInverse(key.modulus), );
        assertEquals(key.modulus, key.prime1.multiply(key.prime2));
        assertEquals(key.exponent1, key.publicExponent.modInverse(p1e));
        assertEquals(key.exponent2, key.publicExponent.modInverse(p2e));
        assertEquals(key.exponent1, key.privateExponent.mod(p1e));
        assertEquals(key.exponent2, key.privateExponent.mod(p2e));
        assertEquals(key.publicExponent, key.privateExponent.modInverse(RSAKeyGen.lcm(p1e,p2e)));
        assertEquals(key.coefficient, key.prime2.modInverse(key.prime1));
//        assertEquals(key.privateExponent, key.exponent1.multiply(key.exponent2).mod(RSA.lcm(p1e, p2e)));
    }

    @Test
    public void testExponent() {
        System.out.println("exponent");
        // pq
        BigInteger n = new BigInteger(Bin.toByteArray("00bbc94dc47beb59498cb693f3438d4cf57716c5961a50eaa8fb004a36c373c5c07a132c5944a5c77bcd0bcf4cc427b729b0caf33ce8ca61c7c4aaf6800a28177d063138f435085fd41acf368170861acd31946a1df983324c6e5e5310193968d251a2c627a58953820d999b6f62504f0f0791e99749fe57cc01aeacebc4da3ba9effe78ad57737aa39cb1c689df932e30e4067461b84714132d20d7264fe79709b1d1d79b2555b6ac217e9e0fb7202df7d0098bb25e7fb3ca875791e72f22ec39a32ae2d7b69d7465ebff43a336ea1db4e9114aa438bb11322ce586f7f154556ab8be0c724e71f42fc3052484df94521948a8d737d9908d84029422f12a5bb2a45ff7a39531907cb5fc86bb8865b7114861b4fa501ac3ab0203f6fac3370fe380464259d084d912f425efba408bca9e927716867bffea073a06c8fe7ffdd42b9d60ee522901b6343350ab1df920cd22f9c342985d4a0fdc0f9caa1a5857f6cc952a74d463f3e412f86936e1ab7e5962c1dc3b61dc24ec4f0ac2058791b75bf6d3"));
        BigInteger e = BigInteger.valueOf(65537);
        BigInteger d = new BigInteger(Bin.toByteArray("05c804769320c37149e813bffe896acacd2d774c7abcee573625b92331d098fafc5c7b6b62d0a91be7a12b1daaeaff6eef7c20119fa7c8c0df63800ea06c16e508d16fcbc7978813bdf639305cfd7e9fbdf20573accb3190e6d3a297b149c784b4c75fcb0d594aa7e0b14fa16b3e710b53beab440c1eccd1d6ba16501fe7096fdeed4fb123d5c5fb24322e46efb4d6a18cb3a22ba157c18776f136e3d2bbf2362087b1ad461b507216349165dc7672292f4f7697398f9197ca4e3e3606de7ab54763804a41858bb45918cc4589ab834acd4768be6420a3377cb9d8c49b834ba619d1343bab58446dce8d9120af8e0aca643da80e0b18d02d106300f68e90635303ed957b20d8ac3e2bc18b53a1fe4d976dac70d58acf52d4d0cf5a1031fd3e21800cbe5d3a042bdd54169ffaf71d604a6d8464d203bd1816d43b45d19222f16df13dbbbced6333cd4d9cf2d9aee907e75876bdaf53a82884b7998854991612dd9aa9f7abfa8556c5a5cc341dcba97ddb61106d2973e3d0737f324a7d0d029621"));
        BigInteger p = new BigInteger(Bin.toByteArray("00d5100a1c84ea8c6eb026e822362a6d1ecb7139d78e06bf4b834c97e4200fac9b47ca31b25a38d748fd35bf451e393397ce3cf7fa6fc64994e3687a9a0d21598e8a01da1b651f18663515dd351ecaa10378e8883120c9d6f9301d22026e1a98188183fc1646f3d34d8652df408de3471a0f2decb5a603aa4db7f06f0fe11798b98199283e301f59df3fd8e09244dc00e69ff14ba1ca9131a8b0f6f66255ba77619a8a12608dd24329758c009fcde5aaf6be6ba62c67c444402a969c98990e0283"));
        BigInteger q = new BigInteger(Bin.toByteArray("00e1a140a243de24ab784370657a4018ac0920ee04829089e19837014a5702df879185970dfef93c9ca29dfed350574fae0d1671dda4780353696db79f1d5c9e9b3235b97bb3da85679718000d7ec232b97a4dabda6c19824e7cca622daed99ea0e230e2b36262dfcb2bb17c5b962861188272f0d8c3274e00dd3107f36549e342f25d086c02153e2915e82193ce057feae9b413d6f1f680816194c86c1497199116edb7d3d63b9a398aed29ca3494da26dc328047b0fc039ab7db500d70bcc971"));
        BigInteger dP = new BigInteger(Bin.toByteArray("00cacfe9d01bf5e897b4b65461bc8dc6317a16dda8825989dea7ad5128a61c4581ca647dc9f87802f64791d1f04944ca07c719e2335212be182c2058142c4b82a45c5a46f3acde5cab6dfcd204aebad36a2abdae66957f8c52c7a9f3a5bc89341e9faab35bc14e77e563e79efc241424aa79a88d9a9bdd014fd9b7d50098938d9d87eff28ebfe017fc9b1a272b14c1175a71058fa902da131b30d8e4cfd62b19589f72aeeb9a147c3a0adaa9fd74511adca5867337f1ceb1e922a11b8f66a21f61"));
        BigInteger dQ = new BigInteger(Bin.toByteArray("2b45bad8a3fd81b8e50ac20ea44090bac5d16bf4af79bb07ea227a7be06e2ba29b752c8041ab59458d26920dc2f5cbd14caf464d44d2c38886cac5119e16fa503773f84bd23591aa495f0ffb869906136e72610835fd3a71851b6772ed7acd227bdef64b830e056fb8c4845e28513c35f026cd2c35595f6b6900934ec9d93eddc30fb6a2c84f7ca9728b1f8d7250b9b4baf78f6a84e34ac80587fc5c4622a8839c0b215b5e55f6011d34d8f3efdbb06f0d821dfa21e6636693e65ad7090d1bf1"));
        BigInteger c = new BigInteger(Bin.toByteArray("4da0d6270bd1fcf09f0c258b6531fc37f9e21edf6d55d7bcd4a87fea477763171290be0aeced35f1eee39b1aad2d51b2e7585702549f28c21ef975f5fe26f28986f6b3455947f95e4ac36be110a405ba37f28b42fd08cd05a05697a58c367ff9f49a3f750249e8bfb06816f89e5aca8a59c7be6b10a73604955bd97a88171bbf3284f3631c845647f52cfcae910a6ad96116c0388ba5880ddd3013ad4b981bc22243920bfcd3ddbd90d47e6f0e4f317a0f846511a1b9856e28c9d4048b802bd2"));
        RSAPrivateCrtKey key = new RSAPrivateCrtKey(n,e,d,p,q,dP,dQ,c);

        BigInteger p1e = key.prime1.subtract(BigInteger.ONE);
        BigInteger p2e = key.prime2.subtract(BigInteger.ONE);
//        assertEquals(key.publicExponent.modInverse(key.modulus), );
        assertEquals(key.modulus, key.prime1.multiply(key.prime2));
        assertEquals(key.exponent1, key.publicExponent.modInverse(p1e));
        assertEquals(key.exponent2, key.publicExponent.modInverse(p2e));
        assertEquals(key.exponent1, key.privateExponent.mod(p1e));
        assertEquals(key.exponent2, key.privateExponent.mod(p2e));
        assertEquals(key.publicExponent, key.privateExponent.modInverse(RSAKeyGen.lcm(p1e,p2e)));
        assertEquals(key.coefficient, key.prime2.modInverse(key.prime1));
    }

}
