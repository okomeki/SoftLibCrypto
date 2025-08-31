package net.siisise.ietf.pkcs1;

import java.math.BigInteger;
import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;
import net.siisise.security.block.RSAES;
import net.siisise.security.block.RSAES_OAEP;
import net.siisise.security.block.RSAES_PKCS1_v1_5;
import net.siisise.security.key.RSAMiniPrivateKey;
import net.siisise.security.key.RSAPublicKey;
import net.siisise.security.sign.RSASSA;
import net.siisise.security.sign.RSASSA_PKCS1_v1_5;

/**
 * RFC 8017 PKCS #1 v2.2
 * https://datatracker.ietf.org/doc/html/rfc8017#appendix-A
 * FIPS PUB 186-5
 * RSA から汎用のものをこっちにまとめ直し
 */
public class PKCS1 {

    public static final OBJECTIDENTIFIER rsadsi = new OBJECTIDENTIFIER("1.2.840.113549");
    public static final OBJECTIDENTIFIER PKCS = rsadsi.sub(1);
    // Appendix C. ASN.1 Module
    public static final OBJECTIDENTIFIER PKCS1 = PKCS.sub(1);
    public static final OBJECTIDENTIFIER PKCS_1 = PKCS1.sub(0,1);
    public static final OBJECTIDENTIFIER rsaEncryption = PKCS1.sub(1);
    public static final OBJECTIDENTIFIER md2WithRSAEncryption =PKCS1.sub(2); // RSASSA_PKCS1_v1_5 MD2
    public static final OBJECTIDENTIFIER md5WithRSAEncryption =PKCS1.sub(4); // RSASSA_PKCS1_v1_5 MD5
    public static final OBJECTIDENTIFIER sha1WithRSAEncryption =PKCS1.sub(5); // RSASSA_PKCS1_v1_5 SHA1
    public static final OBJECTIDENTIFIER id_RSAES_OAEP = PKCS1.sub(7);
    public static final OBJECTIDENTIFIER id_mgf1 = PKCS1.sub(8);
    public static final OBJECTIDENTIFIER id_pSpecified = PKCS1.sub(9);
    public static final OBJECTIDENTIFIER id_RSASSA_PSS = PKCS1.sub(10);
    public static final OBJECTIDENTIFIER sha256WithRSAEncryption =PKCS1.sub(11); // RSASSA_PKCS1_v1_5 SHA-256
    public static final OBJECTIDENTIFIER sha384WithRSAEncryption =PKCS1.sub(12); // RSASSA_PKCS1_v1_5 SHA-384
    public static final OBJECTIDENTIFIER sha512WithRSAEncryption =PKCS1.sub(13); // RSASSA_PKCS1_v1_5 SHA-512
    public static final OBJECTIDENTIFIER sha224WithRSAEncryption =PKCS1.sub(14); // RSASSA_PKCS1_v1_5 SHA-224
    public static final OBJECTIDENTIFIER sha512_224WithRSAEncryption =PKCS1.sub(15); // RSASSA_PKCS1_v1_5 SHA-512/224
    public static final OBJECTIDENTIFIER sha512_256WithRSAEncryption =PKCS1.sub(16); // RSASSA_PKCS1_v1_5 SHA-512/256
// DigestAlgorithm へ
//    public static final OBJECTIDENTIFIER NIST_SHA2 = new OBJECTIDENTIFIER("2.16.840.1.101.3.4.2");
//    public static final OBJECTIDENTIFIER id_sha224 = NIST_SHA2.
    
    /**
     * 4. Data Conversion Primitives
     * 4.1. I2OSP
     * Integer to Octet String primitive
     * 非負数
     * RFC 8017 4.1. I2OSP
     * @param x 変換される非負整数
     * @param xLen 返されるオクテット文字列長
     * @return 長さxLenオクテットの文字列
     */
    public static byte[] I2OSP(BigInteger x, int xLen) {
        byte[] xnum = x.toByteArray();
        if ( xnum.length != xLen ) {
            if ( xnum.length < xLen ) { // 短い
                byte[] t = new byte[xLen];
                System.arraycopy(xnum, 0, t, xLen - xnum.length, xnum.length);
                xnum = t;
            } else if (xnum.length == xLen + 1 && xnum[0] == 0) { // delete flag
                byte[] t = new byte[xLen];
                System.arraycopy(xnum, 1, t, 0, xLen);
                xnum = t;
            } else if ( xnum.length > xLen ) {
                throw new SecurityException("integer too large");
            }
        }
        return xnum;
    }

    /**
     * Octet String to Integer primitive
     * 4.2. OS2IP
     * signed になりそうなものをunsigned に拡張してからBigIntegerにする.
     * @param x octet string to be converted 符号略バイトデータ
     * @return x corresponding nonnegative integer  符号なしBigInteger
     */
    public static BigInteger OS2IP(byte[] x) {
        if (x[0] < 0) { // 符号調整
            byte[] unum = new byte[x.length + 1];
            System.arraycopy(x, 0, unum, 1, x.length);
            x = unum;
        }
        return new BigInteger(x);
    }

    /**
     * 公開鍵によるRSAES OAEP暗号化 仮.
     * 7.Encryption Schemes 暗号化スキーム.
     * 推奨ハッシュ、マスク生成関数は Appendix B
     * LはPKCS #1では未使用
     * 
     * ハッシュはSHA1 で仮 L用とMGF1用の2つが必要
     * 
     * @param pkey 公開鍵 (n, e)
     * @param m メッセージ (モジュラス長 - 2*ハッシュ長(SHA1) - 2)バイト より短いこと
     * @return 暗号化メッセージ
     */
    public static byte[] RSAES_OAEP_encryption(RSAPublicKey pkey, byte[] m) {
        RSAES rsaes = new RSAES_OAEP();
        return rsaes.encrypt(pkey, m);
    }

    /**
     * 秘密鍵によるRSAES OAEP復号. 仮
     * 7.Encryption Schemes
     * ハッシュはSHA1 で仮 L用とMGF1用の2つが必要
     * LはPKCS #1では未使用
     * @param prv 秘密鍵
     * @param c 暗号化メッセージ
     * @return メッセージ
     */
    public static byte[] RSAES_OAEP_decryption(RSAMiniPrivateKey prv, byte[] c) {
        RSAES rsaes = new RSAES_OAEP();
        return rsaes.decrypt(prv, c);
    }

    /**
     * 7.Encryption Schemes 暗号化スキーム.
     * 推奨ハッシュ、マスク生成関数は Appendix B
     * 
     * @deprecated 古い
     * @param pkey 公開鍵 (n, e)
     * @param m メッセージ nよりいろいろ短いこと
     * @return 暗号化メッセージ
     */
    @Deprecated
    public static byte[] RSAES_v1_5_encryption(RSAPublicKey pkey, byte[] m) {
        RSAES rsaes = new RSAES_PKCS1_v1_5();
        return rsaes.encrypt(pkey, m);
    }

    /**
     * 7.Encryption Schemes 暗号化スキーム.
     * 
     * @deprecated 古い
     * @param prv 秘密鍵
     * @param c 暗号化メッセージ
     * @return メッセージ m
     */
    @Deprecated
    public static byte[] RSAES_v1_5_decryption(RSAMiniPrivateKey prv, byte[] c) {
        RSAES rsaes = new RSAES_PKCS1_v1_5();
        return rsaes.decrypt(prv, c);
    }

    /**
     * 8.2.1 Signature generation operation
     * RSASSA-PKCS1_V1_5-SIGN(K, M)
     * @param K 秘密鍵
     * @param M データ
     * @return 署名
     * @deprecated 
     */
    @Deprecated
    public byte[] pkcs1_v1_5_sign(RSAMiniPrivateKey K, byte[] M) {
        RSASSA ssa = new RSASSA_PKCS1_v1_5();
        ssa.update(M);
        return ssa.sign(K);
    }
    
    /**
     * 8.2.2 Signature verification operation
     * @param pub Public Key
     * @param M Message
     * @param S Signature
     * @return verify
     * @deprecated 
     */
    @Deprecated
    public boolean pkcs1_v1_5_verify(RSAPublicKey pub, byte[] M, byte[] S) {
        RSASSA ssa = new RSASSA_PKCS1_v1_5();
        ssa.update(M);
        return ssa.verify(pub, S);
    }

    private BigInteger RSASP1(java.security.interfaces.RSAPrivateKey K, BigInteger m) {
        return m.modPow(K.getPrivateExponent(), K.getModulus());
    }
}
