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
import java.util.Arrays;
import java.util.List;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.parser5234.ABNF5234;
import net.siisise.block.ReadableBlock;
import net.siisise.bnf.BNF;
import net.siisise.bnf.parser.BNFStringParser;
import net.siisise.io.BASE64;
import net.siisise.security.digest.BlockMessageDigest;

/**
 * SHA-crypt.
 * 1:MD5 未対応
 * 5:SHA-256
 * 6:SHA-512
 */
public class DigestCrypt implements ModularCryptFormat {

    private final String pre;
    private final MessageDigest md;
    // 仕様初期値
    private int encodeRounds = 0;

    /**
     *
     * @param prefix
     * @param digestName
     */
    public DigestCrypt(String prefix, String digestName) {
        this(prefix, BlockMessageDigest.getInstance(digestName));
    }
    
    public DigestCrypt(String prefix, MessageDigest digest) {
        pre = prefix;
        md = digest;
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
        String saltt = passenc.encode(salt); // 仮
        //saltt = "saltABCDsaltEFGH";
        return encode(encodeRounds, saltt, pass);
    }

    /**
     * MCF生成.
     * $&lt;ID&gt;$&lt;SALT&gt;$&lt;PWD&gt;
     * 
     * @param rounds N &lt;= 0: default 5000
     * @param salt MD5 最大8文字　SHA 最大16文字
     * @param pass utf-8 72オクテットくらいまでのパスワード
     * @return MCF
     */
    public String encode(int rounds, String salt, String pass) {
        String pwd = encodePwd(rounds, salt, pass);
        // 22.
        StringBuilder sb = new StringBuilder();
        // a) prefix
        sb.append('$').append(pre).append('$');
        // b) rounds
        if (rounds > 0) {
            sb.append("rounds=").append(rounds).append('$');
        }
        sb.append(salt).append('$').append(pwd); // c) salt d) $
        return sb.toString();
    }

    /**
     * pwd の生成.
     *
     * ラウンド数の変更 rounds=&lt;N&gt;$ rounds N 最小 1000 デフォルト 5000 最大 999,999,999
     *
     * @param rounds N &lt;= 0: default 5000
     * @param salt MD5 最大8文字　SHA 最大16文字
     * @param pass utf-8 72オクテットくらいまでのパスワード
     * @return pwd
     */
    String encodePwd(int rounds, String salt, String pass) {
        byte[] passbin = pass.getBytes(StandardCharsets.UTF_8);

        byte[] saltbin = salt.getBytes(StandardCharsets.UTF_8);
        if (saltbin.length > 16) { // 8bit以外考慮せず
            saltbin = Arrays.copyOf(saltbin, 16);
        }

        md.update(passbin); // 5. Add key.
        md.update(saltbin); // 6. Add salt.
        md.update(passbin); // 7. Add key again.
        byte[] digestB = md.digest(); // 8. Now get result of this (32bytes) and add it to the other context.

        /* Prepare for the real work.  */

        // digest Aの計算
        /* 2. Add the key string.  */
        md.update(passbin);
        /* 3. The last part is the salt string. This must be at must 16
           characters and it ends at the first '$' character (for
           compatibility with existing implementations).  */
        md.update(saltbin);  // 3. salt

        // 9. Add for any character in the key one byte of the alternate sum.
        md.update(fill(digestB, passbin.length));
        // 10.

        // 11.
        for (int plen = passbin.length; plen > 0; plen >>>= 1) {
            if ((plen & 1) != 0) { // a
                md.update(digestB);
            } else {               // b
                md.update(passbin);
            }
        }

        // 12. Create intermediate result.
        byte[] digestA = md.digest();
        // 13. Start computation of P byte sequence.
        // 14. For every character in the password add the entire password.
        for (int i = 0; i < passbin.length; i++) {
            md.update(passbin);
        }
        // 15. Finish the digest.
        byte[] digestDP = md.digest();

        // 16. Create byte sequence P.
        byte[] P = fill(digestDP, passbin.length);
        // 17. Starrt computation of S byte sequence.

        // 18. For every character in the password add the entire password.
        int a0 = 16 + (digestA[0] & 0xff);
        for (int i = 0; i < a0; i++) {
            md.update(saltbin);
        }
        // 19. Finish the digest.
        byte[] digestDS = md.digest();
        // 20. Create byte sequence S.
        byte[] S = fill(digestDS, saltbin.length);
        // 21.
        int xround = rounds <= 0 ? 5000 : rounds;
        
        for (int i = 0; i < xround; i++) {
            // a)
            if ((i & 1) != 0) { // b) 奇数ラウンド 1始まりの場合
                md.update(P);
            } else {           // c) 偶数ラウンド
                md.update(digestA); // digestA または 後の digestC
            }
            if ((i % 3) != 0) { // d)
                md.update(S);
            }
            if ((i % 7) != 0) { // e)
                md.update(P);
            }
            if ((i % 2) != 0) { // f)
                md.update(digestA);
            } else {           // g)
                md.update(P);
            }
            // h) digest C と digest Aは同じところで格納
            digestA = md.digest();
        }

        // e)
        byte[] sorted = new byte[digestA.length];
        switch (sorted.length) {
            case 32:
                for (int i = 0; i < 10; i++) {
                    sorted[i * 3 + 2 - ( i      % 3)] = digestA[     i];
                    sorted[i * 3 + 2 - ((i + 1) % 3)] = digestA[10 + i];
                    sorted[i * 3 + 2 - ((i + 2) % 3)] = digestA[20 + i];
                }
                sorted[30] = digestA[30];
                sorted[31] = digestA[31];
                break;
            case 64:
                for (int i = 0; i < 21; i++) {
                    sorted[i * 3 + ((i + 2) % 3)] = digestA[     i];
                    sorted[i * 3 + ((i + 1) % 3)] = digestA[21 + i];
                    sorted[i * 3 + ( i      % 3)] = digestA[42 + i];
                }
                sorted[63] = digestA[63];
                break;
            default:
                throw new IllegalStateException();
        }
        BASE64 pass64 = new BASE64.LE(BASE64.PASSWORD, false, 0);
        return pass64.encode(sorted);
    }

    private byte[] fill(byte[] src, int length) {
        byte[] P = new byte[length];
        int digestLength = src.length;
        int plen;
        for (plen = 0; plen < length - src.length; plen += src.length) {
            System.arraycopy(src, 0, P, plen, digestLength);
        }
        System.arraycopy(src, 0, P, plen, length - plen);
        return P;
    }

    // $<ID>$<SALT>$<PWD>
    static final ABNFReg REG = new ABNFReg();
    static final ABNF ID = REG.rule("id", BNFStringParser.class, ABNF.list("56"));
    static final ABNF ROUND = REG.rule("round", BNFStringParser.class, ABNF5234.DIGIT.x(4, 9));
    static final ABNF ROUNDS = REG.rule("rounds", ABNF.text("rounds=").pl(ROUND, ABNF.bin('$')));
    static final ABNF CODE = REG.rule("code", ABNF5234.ALPHA.or1(ABNF5234.DIGIT, ABNF.binlist("./")));
    static final ABNF SALT = REG.rule("salt", BNFStringParser.class, CODE.x());
    static final ABNF PWD = REG.rule("pwd", BNFStringParser.class, CODE.x());
    static final ABNF DC5 = REG.rule("dc5", ABNF.bin('$').pl(ID, ABNF.bin('$'), ROUNDS.c(), SALT, ABNF.bin('$'), PWD));

    @Override
    public boolean verify(String pass, String code) {
        ReadableBlock rcode = ReadableBlock.wrap(code);
        BNF.Match result = REG.find(rcode, "dc5", "id","round", "salt", "pwd");
        int round = 0;
        if (result == null) {
            return false;
//            throw new IllegalStateException();
        }
        List rounds = result.get(ROUND);
        if (rounds != null) {
            round = Integer.parseInt((String) rounds.get(0));
        }
        String id = (String) result.get(ID).get(0);
        String salt = (String) result.get(SALT).get(0);
        String codepwd = (String)result.get(PWD).get(0);
        if (!id.equals(pre)) {
            return false;
        }

        String pwd = encodePwd(round, salt, pass);
        return codepwd.equals(pwd);
    }

}
