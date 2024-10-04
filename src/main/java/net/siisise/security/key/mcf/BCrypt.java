/*
 * Copyright 2024 okome.
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
package net.siisise.security.key.mcf;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import net.siisise.io.BASE64;
import net.siisise.lang.Bin;
import net.siisise.security.block.Blowfish;

/**
 * bcrypt の適当な実装.
 * 文字コードはUTF-8まで想定する. $2a$ または　#2b$
 * 2aのバグには未対応.
 * opensshで使われていたりするのでつついておく.
 */
public class BCrypt implements ModularCryptFormat {
    
    public static final int DEFAULT_COST = 12;
    
    @Override
    public String generate(String pass) {
        return gen(DEFAULT_COST, pass);
    }

    /**
     * 生成用.
     * saltを中で作る.
     * @param cost 繰り返しのビット数 1&lt;&lt;cost 4..31
     * @param pass UTF-8パスワード 1 から 72バイト
     * @return MCF
     * @throws NoSuchAlgorithmException 
     */
    public String gen(int cost, String pass) {
        byte[] salt = new byte[16];
        try {
            SecureRandom.getInstanceStrong().nextBytes(salt);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
        return encode(cost, salt, pass);
    }

    /**
     * 生成/照合用.
     * @param cost 繰り返しのビット数 1&lt;&lt;cost 4..31
     * @param salt 16byte 乱数
     * @param pass UTF-8パスワード 1 から 72バイト
     * @return MCF
     */
    public String encode(int cost, byte[] salt, String pass) {

        Blowfish fish = EksBlowfishSetup(cost, salt, pass);

        String ctext = "OrpheanBeholderScryDoubt"; // 3block
        int[] itext = Bin.btoi(ctext.getBytes(StandardCharsets.UTF_8));
        for ( int i = 0; i < 64; i++ ) {
            itext = fish.encrypt(itext);
        }

        BASE64 mcf = new BASE64(BASE64.BCRYPT, 0 );
        // checksum 23byte 何故か1バイト減らす
        String checksum = mcf.encode(Bin.itob(itext), 0, 23);
        return "$2b$" + cost + "$" + mcf.encode(salt) + checksum;
    }

    /**
     * BCrypt用Blowfish初期化.
     * @param cost 繰り返しビット長
     * @param salt 塩 128bit
     * @param pass パスワード
     * @return 
     */
    Blowfish EksBlowfishSetup(int cost, byte[] salt, String pass) {
        Blowfish fish = new Blowfish();
        byte[] bytePass = pass.getBytes(StandardCharsets.UTF_8);
        byte[] bytezPass = Arrays.copyOf(bytePass, bytePass.length + 1); // \0 追加
        
        fish.initBcrypt(cost, salt, bytezPass);
        return fish;
    }

    /**
     * パスワード照合.
     * 2a または 2b で一致したときのみtrue
     * @param pass ユーザ入力パスワード
     * @param code　MCF code
     * @return MCFが2a または 2bの場合の照合結果，どちらでもない場合はfalse
     */
    @Override
    public boolean verify(String pass, String code) {
        String[] spp = code.split("\\x24");
        if ( spp[1].equals("2a") || spp[1].equals("2b") ) {
            int cost = Integer.parseInt(spp[2]);
            String textsalt = spp[3].substring(0, 22);
            BASE64 mcf = new BASE64(BASE64.BCRYPT, 0);
            byte[] salt = mcf.decode(textsalt);
            
            String e = encode(cost, salt, pass);
            return code.equals(e);
        }
        return false;
    }
}
