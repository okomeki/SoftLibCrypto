package net.siisise.security;

import net.siisise.security.mac.HMAC;
import java.security.MessageDigest;

/**
 * 鍵導出関数. Key Derivation Function KDF.
 * FIPS 198-1 HMAC-based KDF
 * RFC 5869 HKDF.
 * RFC 6234 US Secure Hash Algorithms (SHA and SHA-based HMAC and HKDF)
 *   7.2. HKDF
 * RFC 8619 HKDFのOID.
 *
 */
public class HKDF {

    private HMAC hmac;

    public HKDF(MessageDigest sha) {
        hmac = new HMAC(sha);
    }
    
    public HKDF(HMAC mac) {
        hmac = mac;
    }

    /**
     *
     * @param salt 塩 (HMAC鍵) null可
     * @param ikm 秘密鍵
     * @param info 付加 null可 saltっぽいもの
     * @param length リクエスト鍵長 (HMACの255倍まで)
     * @return
     */
    public byte[] hkdf(byte[] salt, byte[] ikm, byte[] info, int length) {
        byte[] prk = extract(salt, ikm);
        return expand(prk, info, length);
    }

    /**
     *
     * @param salt 塩 (HMAC鍵)
     * @param ikm 秘密鍵
     * @return 中間鍵
     */
    byte[] extract( byte[] salt, byte[] ikm) {
        if (salt == null) {
            salt = new byte[0];
        }
        hmac.init(salt);
        return hmac.doFinal(ikm);
    }

    /**
     * 鍵長になるまで繰り返し.
     * 
     * @param prk PRK 中間鍵
     * @param info 付加 saltっぽいもの
     * @param length L 鍵長 byte
     * @return OKM output keying maerial (of L octets)
     */
    private byte[] expand(byte[] prk, byte[] info, int length) {
        int l = hmac.getMacLength();
        int n = ((length + l - 1) / l);
        if (info == null) {
            info = new byte[0];
        }
        PacketS pt = new PacketS();
        byte[] t = new byte[0];
        hmac.init(prk);
        byte[] d = new byte[1];
        for (int i = 1; i <= n; i++) {
            hmac.update(t);
            hmac.update(info);
            d[0] = (byte) i;
            t = hmac.doFinal(d);
            pt.write(t);
        }
        byte[] r = new byte[length];
        pt.read(r);
        return r;
    }
}
