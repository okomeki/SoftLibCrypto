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
package net.siisise.security.key.mcf;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.List;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import net.siisise.block.ReadableBlock;
import net.siisise.bnf.BNF;
import net.siisise.bnf.parser.BNFStringParser;
import net.siisise.io.BASE64;
import net.siisise.io.Input;
import net.siisise.security.digest.BlockMessageDigest;

/**
 * SHA-crypt.
 * 1:MD5 5:SHA-256 6:SHA-512
 * まだ未完成
 */
@Deprecated
public class DigestCrypt implements ModularCryptFormat {

    private final String pre;
    private final String alg;
    // 仕様初期値
    private long encodeRounds = 5000;

    /**
     * 
     * @param prefix
     * @param digestName 
     */
    public DigestCrypt(String prefix, String digestName) {
        pre = prefix;
        alg = digestName;
    }

    MessageDigest algorithm() {
        return BlockMessageDigest.getInstance(alg);
    }

    public void setRounds(int c) {
        if (c < 1000) {
            c = 1000;
        }
        if (c > 999999999) {
            c = 999999999;
        }
        encodeRounds = c;
    }

    @Override
    public String generate(String pass) {
        byte[] salt = new byte[12]; // BASE64 16文字

        try {
            SecureRandom.getInstanceStrong().nextBytes(salt);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
        BASE64 passenc = new BASE64(BASE64.PASSWORD, false, 0);
        String saltt = passenc.encode(salt);
        //saltt = "saltABCDsaltEFGH";
        return encode(encodeRounds, saltt, pass);
    }

    /**
     *
     * $<ID>$<SALT>$<PWD>
     *
     * ラウンド数の変更 rounds=<N>$ rounds N 最小 1000 デフォルト 5000 最大 999,999,999
     *
     * @param rounds N
     * @param salt MD5 最大8文字　SHA 最大16文字
     * @param pass utf-8 72オクテットくらいまでのパスワード
     * @return
     */
    String encode(long rounds, String salt, String pass) {
        byte[] passbin = pass.getBytes(StandardCharsets.UTF_8);
        // ToDo: 72オクテット制限を入れる
        if (passbin.length > 72) {
            throw new IllegalStateException();
        }
        
        if (salt.length() > 16) { // 8bit以外考慮せず
            salt = salt.substring(0, 16);
        }
        byte[] saltbin = salt.getBytes(StandardCharsets.UTF_8);
        // digest Bの計算 ビット長と同じサイズに分ける?
        MessageDigest mda = algorithm(); // 1.

        // digest Aの計算
        mda.update(passbin);  // 2.
        mda.update(saltbin);  // 3.

        MessageDigest mdb = algorithm(); // 4.

        mdb.update(passbin); // 5.
        mdb.update(saltbin); // 6.
        mdb.update(passbin); // 7.
        byte[] digestB = mdb.digest(); // 8.

        // 9.
        int dl = mda.getDigestLength(); // bytres
        int bl = passbin.length / dl;
        for (int i = 0; i < bl; i++ ) {
            mda.update(digestB);
        }
//        mda.update(passbin);
        // 10.
        int r = passbin.length % dl;
        mda.update(digestB, 0, r);

        // 11.

        int plen = passbin.length;

        while ( plen > 0) {
            if ((plen & 1) != 0) { // a
                mda.update(digestB);
            } else {               // b
                mda.update(passbin);
            }
            plen >>>= 1;
        }

        // 11. パターン2?
/*        
        for (byte a : passbin) {
            for (int b = 7; b >= 0; b--) {
                boolean f = ((a >>> b) & 1) != 0;
                if (f) {
                    mda.update(digestB);
                } else {
                    mda.update(passbin);
                }
            }
        }
*/
        // 12.
        byte[] digestA = mda.digest();
        // 13.
        MessageDigest dp = algorithm();
        // 14.
        dp.update(passbin);
        // 15.
        byte[] digestDP = dp.digest();
        // 16.
        byte[] P = new byte[passbin.length];
        for (int i = 0; i < bl; i++ ) {
            System.arraycopy(digestDP, 0, P, dl*i, dl);
        }
        System.arraycopy(digestDP, 0, P, dl*bl, r);
        // 17.
        MessageDigest ds = algorithm();
        // 18.
        int a0 = 16 + (digestA[0] & 0xff);
        for (int i = 0; i < a0; i++) {
            ds.update(saltbin);
        }
        // 19.
        byte[] digestDS = ds.digest();
        // 20.
        byte[] S = new byte[saltbin.length];
        for (int i = 0; i < bl; i++) {
            System.arraycopy(digestDS, 0, S, dl*i, dl);
        }
        System.arraycopy(digestDS, 0, S, dl*bl, r);
        // 21.
        for (int i = 1; i <= rounds; i++) {
            // a)
            MessageDigest c = algorithm();
            if ( i % 2 != 0) { // b) 奇数ラウンド 1始まりの場合
                c.update(P);
            } else {           // c) 偶数ラウンド
                c.update(digestA); // digestA または 後の digestC
            }
            if ( i % 3 != 0) { // d)
                c.update(S);
            }
            if ( i % 7 != 0) { // e)
                c.update(P);
            }
            if ( i % 2 == 1) { // f)
                c.update( digestA);
            } else {           // g)
                c.update(P);
            }
            // h) digest C と digest Aは同じところで格納
            digestA = c.digest();
        }
        // 22.
        StringBuilder sb = new StringBuilder();
        // a) prefix
        sb.append('$').append(pre).append('$');
        // b) rounds
        if ( rounds != 5000 ) {
            sb.append("rounds=").append(rounds).append('$');
        }
        sb.append(salt).append('$'); // c) salt d) $
        // e)
        byte[] sorted = new byte[digestA.length];
        switch (sorted.length) {
            case 32:
                for (int i = 0; i < 10; i++) {
                    sorted[i*3 + 2-(i%3)] = digestA[i];
                    sorted[i*3 + 2-((i+1)%3)] = digestA[10+i];
                    sorted[i*3 + 2-((i+2)%3)] = digestA[20+i];
                }   sorted[30] = digestA[30];
                sorted[31] = digestA[31];
                break;
            case 64:
                for (int i = 0; i < 21; i++) {
                    sorted[i*3 + ((i+2)%3)] = digestA[i];
                    sorted[i*3 + ((i+1)%3)] = digestA[21+i];
                    sorted[i*3 + ( i   %3)] = digestA[42+i];
                }   sorted[63] = digestA[63];
                break;
            default:
                throw new IllegalStateException();
        }
        BASE64 pass64 = new BASE64(BASE64.PASSWORD, false, 0);
        sb.append(pass64.encode(sorted));
        return sb.toString();
    }

    static final ABNFReg REG = new ABNFReg();
    static final ABNF ID = REG.rule("id", ABNF.list("56"));
    static final ABNF ROUND = REG.rule("round",BNFStringParser.class, ABNF5234.DIGIT.x(4,9));
    static final ABNF rounds = REG.rule("rounds",  ABNF.text("rounds=").pl(ROUND, ABNF.bin('$')));
    static final ABNF CODE = REG.rule("code", ABNF5234.ALPHA.or(ABNF5234.DIGIT).or(ABNF.binlist("./")));
    static final ABNF SALT = REG.rule("salt",  CODE.x());
    static final ABNF BASEPASS = REG.rule("basepass", CODE.x());
    static final ABNF DC5 = REG.rule("dc5",ABNF.bin('$').pl(ID,ABNF.bin('$'),rounds.c(), SALT,ABNF.bin('$'),BASEPASS));

    @Override
    public boolean verify(String pass, String code) {
        ReadableBlock rcode = ReadableBlock.wrap(code);
        BNF.Match result = REG.find(rcode, "dc5","round","salt");
        long round = 5000;
        if ( result == null) {
            throw new IllegalStateException();
        }
        List rounds = result.get(ROUND);
        if (rounds != null) {
            round = Long.parseLong((String) rounds.get(0));
        }
        String salt = new String(((Input)result.get(SALT).get(0)).toByteArray(), StandardCharsets.UTF_8);
        String mcf = encode(round, salt, pass);
        System.out.println("verify:" + mcf);
        return mcf.equals(code);
    }

}
