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
import java.util.List;
import net.siisise.io.BASE64;
import net.siisise.security.key.BCrypt;

/**
 * bcrypt の適当な実装.
 * 文字コードはUTF-8まで想定する. $2a$ または　#2b$
 * 2aのバグには未対応.
 * opensshで使われていたりするのでつついておく.
 */
public class BCryptMCF implements ModularCryptFormat {
    
//    private static final int[] CTEXT = Bin.btoi("OrpheanBeholderScryDoubt".getBytes(StandardCharsets.UTF_8));
    public static final int DEFAULT_COST = 12;

    /** 生成用 */
    final String prefix;
    private int cost;
    
    public BCryptMCF() {
        this("2b", DEFAULT_COST);
    }

    /**
     * 初期化.
     * 
     * @param count cost
     */
    public BCryptMCF(int count) {
        this("2b", count);
    }

    /**
     * 初期化.
     * 
     * @param prefix 2b から置き換えたい?
     * @param count cost
     */
    public BCryptMCF(String prefix, int count) {
        this.prefix = prefix;
        cost = count;
    }

    /**
     * MCF生成.
     * @param pass 最大72文字まで有効なpassword
     * @return MCF
     */
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

        BCrypt bc = new BCrypt(cost);
        bc.init(cost, salt, 23);
        byte[] bf = bc.kdf(pass.getBytes(StandardCharsets.UTF_8));
/*        
        Blowfish fish = EksBlowfishSetup(cost, salt, pass);

        int[] itext = CTEXT;
        for (int i = 0; i < 64; i++) {
            itext = fish.encrypt(itext);
        }
*/
        BASE64 mcf = new BASE64(BASE64.Type.BCRYPT, 0);
        // checksum 23byte 何故か1バイト減らす
        String checksum = mcf.encode(bf);
        return "$" + prefix + "$" + cost + "$" + mcf.encode(salt) + checksum;
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
            // salt は文字で生成している場合端数ビットも含まれる
            // salt は比較しない (端数でずれることがある)
            String spv  = spp[3].substring(22);
            String espv = espp[3].substring(22);
            return spv.equals(espv);
        }
        return false;
    }
}
