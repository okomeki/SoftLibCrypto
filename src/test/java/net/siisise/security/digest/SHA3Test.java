/*
 * Copyright 2023 Siisise Net.
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
package net.siisise.security.digest;

import java.io.IOException;
import java.security.Provider;
import java.util.Arrays;
import net.siisise.lang.Bin;
import net.siisise.security.SiisiseJCA;
import static org.junit.jupiter.api.Assertions.*;
import org.junit.jupiter.api.Test;

/**
 *
 */
public class SHA3Test {
    
    public SHA3Test() {
    }
    
    static String SHA3224abc = "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf";
    static String SHA3256abc = "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532";
    static String SHA3384abc = "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25";
    static String SHA3512abc = "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0";
    static String SHAKE128256abc = "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8";
    static String SHAKE256512abc = "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4";
    static String Keccak224abc = "c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8";
    static String Keccak256abc = "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45";
    static String Keccak384abc = "f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e";
    static String Keccak512abc = "18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96";


    // ""
    static String SHA3224 = "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7";
    static String SHA3256 = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a";
    static String SHA3384 = "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004";
    static String SHA3512 = "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26";
    static String SHAKE25632 = "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f";
    static String Keccak224 = "f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd";
    static String Keccak256 = "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470";
    static String Keccak384 = "2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff";
    static String Keccak512 = "0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e";

    @Test
    public void testSomeMethod() throws IOException {
        Keccak md;
        byte[] r;
        byte[] src = "abc".getBytes("utf-8");
        
        md = new SHA3(224);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHA3224abc));

        md = new SHA3(256);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHA3256abc));
        
        md = new SHA3(384);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHA3384abc));
        
        md = new SHA3(512);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHA3512abc));

        md = new SHAKE128(256);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHAKE128256abc));

        md = new cSHAKE128(256, "", "");
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHAKE128256abc));

        md = new SHAKE256(512);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHAKE256512abc));

        md = new cSHAKE256(512, "", "");
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHAKE256512abc));

        md = new Keccak(224);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(Keccak224abc));

        md = new Keccak(256);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(Keccak256abc));

        md = new Keccak(384);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(Keccak384abc));

        md = new Keccak(512);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(Keccak512abc));

        src = "".getBytes();
        md = new SHA3(224);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHA3224));

        md = new SHA3(256);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHA3256));
        
        md = new SHA3(384);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHA3384));
        
        md = new SHA3(512);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHA3512));

        md = new SHAKE256(256);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHAKE25632));

        md = new cSHAKE256(256,"","");
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(SHAKE25632));

        md = new Keccak(448,224);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(Keccak224));

        md = new Keccak(512,256);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(Keccak256));

        md = new Keccak(768,384);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(Keccak384));

        md = new Keccak(1024,512);
        r = md.digest(src);
        assertArrayEquals(r,Bin.toByteArray(Keccak512));

        Provider p = new SiisiseJCA();
    }
    
    @Test
    public void test1600() {
        System.out.println("SHAKE128 1600bit");
        byte[] input = new byte[200];
        Arrays.fill(input, (byte)0xa3);
        SHAKE shake128 = new SHAKE128(512*8);
        shake128.update(input);
        byte[] result = shake128.digest();
        byte[] example = Bin.toByteArray(
                    "131ab8d2b594946b9c81333f9bb6e0ce"
                  + "75c3b93104fa3469d3917457385da037"
                  + "cf232ef7164a6d1eb448c8908186ad85"
                  + "2d3f85a5cf28da1ab6fe343817197846"
                  + "7f1c05d58c7ef38c284c41f6c2221a76"
                  + "f12ab1c04082660250802294fb871802"
                  + "13fdef5b0ecb7df50ca1f8555be14d32"
                  + "e10f6edcde892c09424b29f597afc270"
                  + "c904556bfcb47a7d40778d390923642b"
                  + "3cbd0579e60908d5a000c1d08b98ef93"
                  + "3f806445bf87f8b009ba9e94f7266122"
                  + "ed7ac24e5e266c42a82fa1bbefb7b8db"
                  + "0066e16a85e0493f07df4809aec084a5"
                  + "93748ac3dde5a6d7aae1e8b6e5352b2d"
                  + "71efbb47d4caeed5e6d633805d2d323e"
                  + "6fd81b4684b93a2677d45e7421c2c6ae"
                  + "a259b855a698fd7d13477a1fe53e5a4a"
                  + "6197dbec5ce95f505b520bcd9570c4a8"
                  + "265a7e01f89c0c002c59bfec6cd4a5c1"
                  + "09258953ee5ee70cd577ee217af21fa7"
                  + "0178f0946c9bf6ca8751793479f6b537"
                  + "737e40b6ed28511d8a2d7e73eb75f8da"
                  + "ac912ff906e0ab955b083bac45a8e5e9"
                  + "b744c8506f37e9b4e749a184b30f43eb"
                  + "188d855f1b70d71ff3e50c537ac1b0f8"
                  + "974f0fe1a6ad295ba42f6aec74d123a7"
                  + "abedde6e2c0711cab36be5acb1a5a11a"
                  + "4b1db08ba6982efccd716929a7741cfc"
                  + "63aa4435e0b69a9063e880795c3dc5ef"
                  + "3272e11c497a91acf699fefee206227a"
                  + "44c9fb359fd56ac0a9a75a743cff6862"
                  + "f17d7259ab075216c0699511643b6439"
                );
        assertArrayEquals(example, result);
    }
    
}
