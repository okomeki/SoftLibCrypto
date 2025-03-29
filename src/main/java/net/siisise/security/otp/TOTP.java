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
import java.security.MessageDigest;
import java.util.Calendar;
import net.siisise.abnf.ABNF;
import net.siisise.abnf.ABNFReg;
import net.siisise.abnf.rfc.URI3986;
import net.siisise.io.BASE32;
import net.siisise.lang.Bin;
import net.siisise.security.digest.SHA1;
import net.siisise.security.digest.SHA256;
import net.siisise.security.digest.SHA512;

/**
 * RFC 6238 Time-based One-time Password Algorithm (TOTP).
 * HOTPを利用しているらしい.
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
    static final ABNF issuer = reg.rule("issuer", uricode.ix());
    static final ABNF accountname = reg.rule("accountname", uricode.ix());
    static final ABNF label = reg.rule("label", issuer.pl(ABNF.bin(':').or(ABNF.text("%3A"))).c().pl(ABNF.text("%20").x(), accountname));

    HOTP hotp;
    /**
     * 秘密鍵.
     */
    private byte[] secret;
    int digit;
    /**
     * 秒間隔. でふぉると 30秒
     */
    long period = 30;
    String alg = "SHA1";

    public TOTP() {
        this(new SHA1());
    }

    public TOTP(MessageDigest md) {
        hotp = new HOTP(md);
    }

    public void setSecret(byte[] k) {
        hotp.setKey(k);
        this.secret = k.clone();
    }

    public void setDigit(int digit) {
        hotp.setDigit(digit);
        this.digit = digit;
    }

    @Override
    public String generateOTP(byte[] counter) {
        return hotp.generateOTP(counter);
    }

    public String generateOTP(long counter) {
        return generateOTP(Bin.ltob(new long[]{counter}));
    }

    public String generateOTP() {
        long time = Calendar.getInstance().getTimeInMillis() / 1000;
        return hotp.generateOTP(time / period);
    }
    
    /**
     * 確認する.
     * n分以内に入力っぽいものの遅延に対応しておく.
     * 15分など長期は1つ生成してこれは使わないほうがいいかも.
     * 長時間有効にする場合は8桁くらいはほしい
     * 40秒を指定すると40から60秒前に生成されたものが有効になったりならなかったりする。
     * @param code 手入力
     * @param sec 最小何秒前まで有効か、ぐらいの感じで使いたい period の単位で区切られる
     * @return true 一致
     */
    public boolean validateOTP(String code, int sec) {
        long time = Calendar.getInstance().getTimeInMillis() / 1000;
        long start = (time - sec) / period;
        long end = time / period;
        for ( long t = end; t >= start; t-- ) {
            String genCode = hotp.generateOTP(t);
            if ( genCode.equals(code) ) {
                return true;
            }
        }
        return false;
    }

    String secretEncode(byte[] secret) {
        BASE32 b32 = new BASE32(BASE32.BASE32);
        return b32.encode(secret);
    }

    byte[] secretDecode(String base32) {
        BASE32 b32 = new BASE32(BASE32.Type.BASE32FIX);
        return b32.decode(base32);
    }

    MessageDigest toMD(String algorithm) {
        MessageDigest md;

        if (algorithm == null || "SHA1".equals(algorithm)) {
            md = new SHA1();
        } else if ("SHA256".equals(algorithm)) {
            md = new SHA256();
        } else if ("SHA512".equals(algorithm)) {
            md = new SHA512();
        } else {
            throw new UnsupportedOperationException("Unknown algorithm");
        }
        return md;
    }
    
    String toAlg(MessageDigest md) {
        return md.getAlgorithm();
    }
    
    /**
     * otpauth URI otpauth://TYPE/LABEL?PARAMETERS type = hotp または totp totpのみ
     * label = accountname / issuer (":" / "%3A") *"%20" accountname
     *
     * otpauth://totp/
     *
     * @param secret
     * @return
     */
    public URI generateKeyURI(byte[] secret, String accountname, String issuer, String algorithm, int digits) {
        
        // 型チェック
        toMD(algorithm);
        //alg = algorithm;

        if ( !TOTP.issuer.is(issuer)) {
            throw new IllegalStateException("issuer " + issuer);
        }
        if ( !TOTP.accountname.is(accountname)) {
            throw new IllegalStateException("accountname " + issuer);
        }
        String label = issuer + ":" + accountname;

        String sec = secretEncode(secret);

        String base = "otpauth://totp/" + label + "?secret=" + sec + "&issuer=" + issuer;

        if (algorithm != null) {
            base += "&algorithm=" + algorithm;
        }
        if (digits != 6) {
            base += "&digits=" + digits;
        }

        try {
            return new URI(base);
        } catch (URISyntaxException ex) {
            throw new IllegalStateException(ex);
        }
    }
    
    public URI generateKeyURI(byte[] secret, String accountname, String issuer) {
        return generateKeyURI(secret, accountname, issuer, alg, digit);
    }

    public URI generateKeyURI(String secret, String accountname, String issuer, String algorithm, int digits) {
        byte[] sec = secretDecode(secret);
        return generateKeyURI(sec, accountname, issuer, algorithm, digits);
    }

    public URI generateKeyURI(String secret, String accountname, String issuer) {
        return generateKeyURI(secret, accountname, issuer, alg, digit);
    }

    public URI generateKeyURI(String accountname, String issuer) {
        return generateKeyURI(secret, accountname, issuer);
    }

    public void init(URI uri) {
        if (!"otpauth".equals(uri.getScheme()) || !"totp".equals(uri.getHost())) {
            throw new IllegalStateException();
        }
        String path = uri.getPath();
        String query = uri.getQuery();
        
        
        throw new UnsupportedOperationException("まだない");
    }
}
