package net.siisise.security.mac;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.SecretKeySpec;
import net.siisise.security.digest.BlockMessageDigest;

/**
 * The Keyed-Hash Message Authentication Code (HMAC) FIPS 198-1.
 * Java標準ではない仮の鍵付きハッシュの形. あとで標準に寄せる。
 * ISO/IEC 10118 か ISO/IEC 9796
 * H 暗号ハッシュ関数.
 * K 秘密鍵 / 認証鍵.
 * B Hのブロックバイト長 512 / 8
 * L ハッシュバイト長 (MD5:128/8 SHA-1:160/8)
 * ipad 0x36をB回繰り返したもの
 * opad 0x5c をB回繰り返したもの
 *
 * 対応可能なアルゴリズム
 * HMAC-MD5         B  512bit L 128bit
 * HMAC-MD5-96      B  512bit L  96bit
 * HMAC-SHA-1       B  512bit L 160bit
 * HMAC-SHA-1-96    B  512bit L  96bit
 * HMAC-SHA-224     B  512bit L 224bit
 * HMAC-SHA-256     B  512bit L 256bit
 * HMAC-SHA-384     B 1024bit L 384bit
 * HMAC-SHA-512     B 1024bit L 512bit
 * HMAC-SHA-512/224 B 1024bit L 224bit
 * HMAC-SHA-512/256 B 1024bit L 256bit
 * HMAC-SHA3-224    B 1152bit L 224bit
 * HMAC-SHA3-256    B 1088bit L 256bit
 * HMAC-SHA3-384    B  832bit L 384bit
 * HMAC-SHA3-512    B  576bit L 512bit
 *
 * FIPS PUB 198-1
 * FIPS 202 7 Conformance SHA-3のHMAC
 * RFC 2104 HMAC: Keyed-Hashing for Message Authentication.
 * RFC 2202 テスト
 * RFC 4231 Identifiers and Test Vector for HMAC-SHA-224, HMAC-SHA-256,
 *                          HMAC-SHA-384, and HMAC-SHA-512
 */
public class HMAC implements MAC {

    public static final String rsadsi = "1.2.840.113549";
    public static final String digestAlgorithm = rsadsi + ".2";
    public static final String idhmacWithSHA224 = digestAlgorithm + ".8";
    public static final String idhmacWithSHA256 = digestAlgorithm + ".9";
    public static final String idhmacWithSHA384 = digestAlgorithm + ".10";
    public static final String idhmacWithSHA512 = digestAlgorithm + ".11";

//    private HMACSpi spi;
    private MessageDigest md;
    int blockLength;
    private byte[] k_ipad;
    private byte[] k_opad;

    /**
     * ブロック長 512ビット または Spec対応用.
     *
     * @param md MD5, SHA-1, SHA-256 など(汎用)512bitブロックのもの または
     * MessageDigestSpec対応版
     * @param key 鍵 ブロック長 512bitのもの.
     */
    public HMAC(MessageDigest md, byte[] key) {
//        spi = new HMACSpi();
        this.md = md;
        if (md instanceof BlockMessageDigest) {
            blockLength = ((BlockMessageDigest) md).getBitBlockLength();
        } else {
            blockLength = 512;
        }
        init(key);
    }

    /**
     * HMACの初期設定.
     * アルゴリズムが指定可能なのでkeyのみでdigestも指定可能.
     *
     * @param key アルゴリズムと鍵.
     */
    public HMAC(SecretKeySpec key) {
        blockLength = 512;
        init(key);
    }

    /**
     * ブロック長 1024ビットなど用(仮).
     *
     * @param md SHA-384, SHA-512, SHA-512/224, SHA-512/256, SHA-3
     * @param blockBitLength
     * @param key
     */
    public HMAC(MessageDigest md, int blockBitLength, byte[] key) {
        this.md = md;
        blockLength = blockBitLength;
        init(key);
    }

    public HMAC(MessageDigest md, int blockBitLength, SecretKeySpec key) {
        this.md = md;
        blockLength = blockBitLength;
        init(key);
    }

    /**
     * 鍵とアルゴリズムの指定.
     *
     * @param key
     */
    public void init(SecretKeySpec key) {
        String alg = key.getAlgorithm().toUpperCase();
        if (alg.startsWith("HMAC-")) { // RFC系の名前?
            md = (MessageDigest) BlockMessageDigest.getInstance(key.getAlgorithm().substring(5));
        } else if (alg.startsWith("HMAC")) {
            try {  // Java系の名前
                md = MessageDigest.getInstance(alg.substring(4));
            } catch (NoSuchAlgorithmException ex) {
                if (md == null) {
                    throw new SecurityException(ex);
                }
            }

        } else {
            throw new java.lang.UnsupportedOperationException();
        }
        this.md = md;
        if (md instanceof BlockMessageDigest) {
            blockLength = ((BlockMessageDigest) md).getBitBlockLength();
        }
        init(key.getEncoded());
    }

    /**
     * 
     * @return バイト長
     */
    @Override
    public int getMacLength() {
        return md.getDigestLength();
    }

    /**
     * 鍵.
     * L以上の長さが必要.
     * B以上の場合はハッシュ値に置き換える.
     *
     * @param key 鍵
     */
    public void init(byte[] key) {
        int b = blockLength / 8;
        md.reset();
        if (key.length > b) {
            key = md.digest(key);
        }

        k_ipad = new byte[b];
        k_opad = new byte[b];

        System.arraycopy(key, 0, k_ipad, 0, key.length);
        System.arraycopy(key, 0, k_opad, 0, key.length);

        for (int i = 0; i < b; i++) {
            k_ipad[i] ^= 0x36;
            k_opad[i] ^= 0x5c;
        }
        md.update(k_ipad);
    }

    @Override
    public void update(byte[] src) {
        md.update(src, 0, src.length);
    }

    @Override
    public void update(byte[] src, int offset, int len) {
        md.update(src, offset, len);
    }

    /**
     *
     * @param src
     * @return HMAC値
     */
    public byte[] doFinal(byte[] src) {
        byte[] m = md.digest(src);

        md.update(k_opad);
        byte[] r = md.digest(m);
        md.update(k_ipad);
        return r;
    }

}
