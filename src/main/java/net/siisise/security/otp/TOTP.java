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
package net.siisise.security.otp;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.rfc.URI3986;
import net.siisise.block.ReadableBlock;
import net.siisise.bnf.BNF;
import net.siisise.io.BASE32;
import net.siisise.io.Packet;
import net.siisise.lang.Bin;
import net.siisise.security.digest.BlockMessageDigest;
import net.siisise.security.digest.SHA1;
import net.siisise.security.mac.HMAC;
import net.siisise.security.mac.MAC;

/**
 * RFC 6238 Time-based One-time Password Algorithm (TOTP). HOTPを利用しているらしい.
 * URIを扱うので分けたい
 */
public class TOTP implements OTP {

    static final ABNFReg reg = new ABNFReg(URI3986.REG);
    // space, : 不可なASCII内 (とりあえず)
//    ABNF escape = reg.rule("esacape",ABNF.bin('%').pl(ABNF5234.HEXDIG.x(2)));
//    ABNF uriesc = reg.rule("uriesc", escape.mn(ABNF.bin('%').pl(ABNF.text("3A"))));
//    ABNF uricode = reg.rule("uricode", uriesc.or1(ABNF.range(0x21,0x24).or(0x26,0x39).or(0x3b,0x7e).x()));
    static final ABNF uch = reg.rule("uch", URI3986.unreserved.or1(reg.ref("pct-encoded"), reg.ref("sub-delims"), ABNF.bin('@'))); // segment-nz-nc
    static final ABNF uricode = reg.rule("uricode", uch.mn(ABNF.bin('%').pl(ABNF.text("3A"))));
    static final ABNF ISSUER = reg.rule("issuer", uricode.ix());
    static final ABNF ACCOUNTNAME = reg.rule("accountname", uricode.ix());
    static final ABNF LABEL = reg.rule("label", ISSUER.pl(ABNF.bin(':').or(ABNF.text("%3A"))).c().pl(ABNF.text("%20").x(), ACCOUNTNAME));

    HOTP hotp;
    /**
     * 秘密鍵.
     */
    private byte[] secret;
    int digit = 8;
    /**
     * 秒間隔. でふぉると 30秒
     */
    long period = 30;
    String alg = "SHA1";

    // label
    String issuer;
    String accountname;
    String label;

    public TOTP() {
        this("SHA1");
    }

    /**
     * 未. HOTPのHMAC用ハッシュ ToDo: アルゴリズムの扱いが未定
     *
     * @param alg ハッシュ識別名
     */
    public TOTP(String alg) {
        hotp = new HOTP(toMD(alg));
        this.alg = alg;
    }

    /**
     * HOTPのMACアルゴリズムHMAC以外も指定可能.
     *
     * @param mac MACアルゴリズム 非互換 KMAC, CMACなどもあり
     * @param alg ハッシュ識別名
     */
    public TOTP(MAC mac, String alg) {
        hotp = new HOTP(mac);
    }

    /**
     * 鍵の設定.
     *
     * @param k 鍵
     */
    public void setSecret(byte[] k) {
        hotp.setKey(k);
        this.secret = k.clone();
    }

    public byte[] getSecret() {
        return secret.clone();
    }

    /**
     * 出力桁数の指定.
     *
     * @param digit 桁数
     */
    public void setDigit(int digit) {
        hotp.setDigit(digit);
        this.digit = digit;
    }

    /**
     * 更新間隔(秒)の指定.
     *
     * @param period 間隔(sec)
     */
    public void setPeriod(long period) {
        this.period = period;
    }

    /**
     * TOTP
     *
     * @deprecated validateOTP
     * @param counter
     * @return
     */
    @Override
    @Deprecated
    public String generateOTP(byte[] counter) {
        return hotp.generateOTP(counter);
    }

    public String generateOTP(long counter) {
        return generateOTP(Bin.ltob(new long[]{counter}));
    }

    /**
     * クライアント側に必要そうな情報.
     *
     * @return
     */
    public String generateOTP() {
        long time = Calendar.getInstance().getTimeInMillis() / 1000;
        return hotp.generateOTP(time / period);
    }

    /**
     * 残り秒数.
     *
     * @return 残り秒数
     */
    public int limit() {
        long time = Calendar.getInstance().getTimeInMillis() / 1000;
        return (int) (time % period);
    }

    /**
     * 確認する. n分以内に入力っぽいものの遅延に対応しておく. 15分など長期は1つ生成してこれは使わないほうがいいかも.
     * 長時間有効にする場合は8桁くらいはほしい 40秒を指定すると40から60秒前に生成されたものが有効になったりならなかったりする。
     *
     * @param code 手入力
     * @param sec 最小何秒前まで有効か、ぐらいの感じで使いたい period の単位で区切られる
     * @param time ミリ秒 (Java標準)
     * @return true 一致
     */
    public boolean validateOTP(String code, int sec, long time) {
        time = time / 1000;
        long start = (time - sec) / period;
        long end = time / period;
        for (long t = end; t >= start; t--) {
            String genCode = hotp.generateOTP(t);
            if (genCode.equals(code)) {
                return true;
            }
        }
        return false;
    }

    /**
     * 確認する. n分以内に入力っぽいものの遅延に対応しておく. 15分など長期は1つ生成してこれは使わないほうがいいかも.
     * 長時間有効にする場合は8桁くらいはほしい 40秒を指定すると40から60秒前に生成されたものが有効になったりならなかったりする。
     *
     * @param code 手入力
     * @param sec 最小何秒前まで有効か、ぐらいの感じで使いたい period の単位で区切られる
     * @return true 一致
     */
    public boolean validateOTP(String code, int sec) {
        long time = Calendar.getInstance().getTimeInMillis();
        return validateOTP(code, sec, time);
    }

    String encodeSecret(byte[] secret) {
        BASE32 b32 = new BASE32(BASE32.BASE32);
        return b32.encode(secret);
    }

    byte[] decodeSecret(String base32) {
        BASE32 b32 = new BASE32(BASE32.Type.BASE32FIX);
        return b32.decode(base32);
    }

    static MessageDigest toMD(String algorithm) {
        MessageDigest md;

        //md = BlockMessageDigest.getInstance(algorithm);
        if (algorithm == null || "SHA1".equals(algorithm)) {
            md = new SHA1();
        } else {
            md = BlockMessageDigest.getInstance(algorithm);
            if (md == null) {
                throw new UnsupportedOperationException("Unknown algorithm " + md);
            }
        }
        return md;
    }

    /**
     * encodeURI と encodeURIComponent と URI3986版といろいろある.
     *
     * @param src
     * @return
     */
    static String pcharEncode(String src) {
        return URI3986.pcharPercentEncode(src);
    }

    static String queryKeyValueEncode(String src) {
        return URI3986.queryKeyValuePercentEncode(src);
    }

    String pcharDecode(String src) {
        return URI3986.urlPercentDecode(src);
    }

    /**
     * otpauth URI otpauth://TYPE/LABEL?PARAMETERS type = hotp または totp totpのみ
     * label = accountname / issuer (":" / "%3A") *"%20" accountname
     *
     * otpauth://totp/
     *
     * @param secret 鍵
     * @param accountname アカウント名
     * @param issuer 発行者
     * @param algorithm アルゴリズム null で SHA1
     * @param digits 桁数
     * @return
     */
    public URI generateKeyURI(byte[] secret, String accountname, String issuer, String algorithm, int digits, long period) {

        // 型チェック
        toMD(algorithm);
        //alg = algorithm;

        StringBuilder uri = new StringBuilder("otpauth://totp/");

        String kvIssuer;
        if (issuer != null) {
            kvIssuer = queryKeyValueEncode(issuer);
            String pcIssuer = pcharEncode(issuer);
            if (!TOTP.ISSUER.eq(pcIssuer)) {
                throw new IllegalStateException("issuer " + issuer);
            }
            uri.append(pcIssuer).append(':');
        } else {
            kvIssuer = null;
        }

        accountname = pcharEncode(accountname);

        if (!TOTP.ACCOUNTNAME.eq(accountname)) {
            throw new IllegalStateException("accountname " + accountname);
        }

        String sec = encodeSecret(secret);

        uri.append(accountname).append("?secret=").append(sec);
        if (issuer != null) {
            uri.append("&issuer=").append(kvIssuer);
        }

        if (algorithm != null && !algorithm.equals("SHA1")) {
            uri.append("&algorithm=").append(algorithm);
        }
        if (digits != 6) {
            uri.append("&digits=").append(digits);
        }
        if (period != 30) {
            uri.append("&period=").append(period);
        }

        try {
            return new URI(uri.toString());
        } catch (URISyntaxException ex) {
            throw new IllegalStateException(ex);
        }
    }
    
    public URI generateKeyURI(byte[] secret, String accountname, String issuer) {
        return generateKeyURI(secret, accountname, issuer, alg, digit, period);
    }

    public URI generateKeyURI(String secret, String accountname, String issuer, String algorithm, int digits, long period) {
        byte[] sec = decodeSecret(secret);
        return generateKeyURI(sec, accountname, issuer, algorithm, digits, period);
    }

    public URI generateKeyURI(String secret, String accountname, String issuer) {
        return generateKeyURI(secret, accountname, issuer, alg, digit, period);
    }

    /**
     * アカウントとissuerでtotp URI生成
     * @param accountname アカウント
     * @param issuer 発行者名
     * @return TOTP URI
     */
    public URI generateKeyURI(String accountname, String issuer) {
        if (secret == null) {
            try {
                setSecret(hotp.genKey());
            } catch (NoSuchAlgorithmException ex) {
                throw new IllegalStateException(ex);
            }
        }

        return generateKeyURI(secret, accountname, issuer);
    }

    public URI generateKeyURI() {
        return generateKeyURI(accountname, issuer);
    }

    /**
     * KeyURIから設定を復元する.
     *
     * @param keyuri
     */
    public void init(URI keyuri) {
        if (!"otpauth".equals(keyuri.getScheme()) || !"totp".equals(keyuri.getHost())) {
            throw new IllegalStateException();
        }
//        String label = keyuri.getPath();
        label = keyuri.getPath().substring(1);
        ReadableBlock localBlock = ReadableBlock.wrap(label);
        BNF.Match r = reg.find(localBlock, "label", "issuer", "accountname");
        List<Packet> isl = r.get("issuer");
        List<Packet> acl = r.get("accountname");
        if (isl != null) {
            issuer = pcharDecode(new String(isl.get(0).toByteArray(), StandardCharsets.UTF_8));
        }
        if (acl != null) {
            accountname = pcharDecode(new String(acl.get(0).toByteArray(), StandardCharsets.UTF_8));
        }

        String query = keyuri.getQuery();
        Map<String, String> queryMap = parseQuery(query);
        String sec = queryMap.get("secret");
        String queryIssuer = queryMap.get("issuer");
        String algorithm = queryMap.get("algorithm");
        String digits = queryMap.get("digits");
        String period = queryMap.get("period");
        hotp = new HOTP(new HMAC(toMD(algorithm)));
        this.alg = algorithm;
        if (queryIssuer != null) { // パラメータが優先 (仮)
            issuer = queryIssuer;
        }
        setSecret(decodeSecret(sec));
        if (digits != null) {
            setDigit(Integer.parseInt(digits));
        }
        if (period != null) {
            setPeriod(Long.parseLong(period));
        }
    }

    /**
     * パラメータのパース ToDo:デコード済みのものにする
     *
     * @param query
     * @return
     */
    Map<String, String> parseQuery(String query) {
        Map<String, String> q = new HashMap<>();
        String[] split = query.split("&");
        for (String n : split) {
            String[] v = n.split("=", 2);
            if (v.length == 1) {
                q.put(pcharDecode(n), null);
            } else {
                q.put(pcharDecode(v[0]), pcharDecode(v[1]));
            }
        }
        return q;
    }
}
