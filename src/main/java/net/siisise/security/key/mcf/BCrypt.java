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
import java.util.List;
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
    
    static final byte[] CTEXT = "OrpheanBeholderScryDoubt".getBytes(StandardCharsets.UTF_8);

    String prefix;
    public static final int DEFAULT_COST = 12;
    private int cost;
    
    public BCrypt() {
        this("$2b$", DEFAULT_COST);
    }

    /**
     * 
     * @param count cost
     */
    public BCrypt(int count) {
        this("$2b$", count);
    }

    /**
     * 
     * @param prefix $2b$ から置き換えたい?
     * @param count cost
     */
    public BCrypt(String prefix, int count) {
        this.prefix = prefix;
        cost = count;
    }

    @Override
    public String generate(String pass) {
        return gen(cost, pass);
    }

    /**
     * 生成用.
     * saltを中で作る.
     *
     * @param cost 繰り返しのビット数 1&lt;&lt;cost 4..31
     * @param pass UTF-8パスワード 1 から 72バイト
     * @return MCF
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
     *
     * @param cost 繰り返しのビット数 1&lt;&lt;cost 4..31
     * @param salt 16byte 乱数
     * @param pass UTF-8パスワード 1 から 72バイト
     * @return MCF
     */
    public String encode(int cost, byte[] salt, String pass) {

        Blowfish fish = EksBlowfishSetup(cost, salt, pass);

        int[] itext = Bin.btoi(CTEXT);
        for (int i = 0; i < 64; i++) {
            itext = fish.encrypt(itext);
        }

        BASE64 mcf = new BASE64(BASE64.Type.BCRYPT, 0);
        // checksum 23byte 何故か1バイト減らす
        String checksum = mcf.encode(Bin.itob(itext), 0, 23);
        return prefix + cost + "$" + mcf.encode(salt) + checksum;
    }

    /**
     * BCrypt用Blowfish初期化.
     *
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
     *
     * @param pass ユーザ入力パスワード
     * @param code　MCF code
     * @return MCFが2a または 2bの場合の照合結果，どちらでもない場合はfalse
     */
    @Override
    public boolean verify(String pass, String code) {
        List<String> hds = List.of("2", "2a", "2x", "2y", "2b");
        String[] spp = code.split("\\x24");
        if (hds.contains(spp[1])) {
            int mcfCost = Integer.parseInt(spp[2]);
            String textsalt = spp[3].substring(0, 22);
            BASE64 mcf = new BASE64(BASE64.Type.BCRYPT, 0);
            byte[] salt = mcf.decode(textsalt);

            String e = encode(mcfCost, salt, pass);
            String[] espp = e.split("\\x24");
            return spp[3].equals(espp[3]);
        }
        return false;
    }
}
