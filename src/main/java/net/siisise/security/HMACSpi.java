package net.siisise.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.MacSpi;
import javax.crypto.spec.SecretKeySpec;
import net.siisise.security.digest.MessageDigestSpec;

/**
 * まだ
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
 */
public class HMACSpi extends MacSpi {
    
    MessageDigest md;
    private byte[] k_ipad;
    private byte[] k_opad;
    
//    static Map<String,String> aliases = new HashMap();
    
//    static {
//        aliases.put("HmacMD5", "MD5");
//        aliases.put("HmacMD5-96", "MD5-96");
//        aliases.put("HmacSHA1","SHA-1");
//        aliases.put("HmacSHA224", "SHA-224");
//        aliases.put("HmacSHA256", "SHA-256");
//        aliases.put("HmacSHA384", "SHA-384");
//        aliases.put("HmacSHA512", "SHA-512");
//        aliases.put("HmacSHA512/224", "SHA-512/224");
//        aliases.put("HmacSHA512/256", "SHA-512/256");
//        aliases.put("HmacSHA3-224", "SHA3-224");
//        aliases.put("HmacSHA3-256", "SHA3-256");
//        aliases.put("HmacSHA3-384", "SHA3-384");
//        aliases.put("HmacSHA3-512", "SHA3-512");
//    }
    
    public HMACSpi() {
    }

    @Override
    protected void engineInit(Key key, AlgorithmParameterSpec aps) throws InvalidKeyException, InvalidAlgorithmParameterException {
        SecretKeySpec spec = (SecretKeySpec) key;
        String alg = spec.getAlgorithm().toUpperCase();
        int b;
        if ( alg.startsWith("HMAC")) {
            int l = (alg.length() > 4 && alg.charAt(4) == '-') ? 5 : 4;
            MessageDigestSpec mds;
            try {
                mds = MessageDigestSpec.getInstance(alg.substring(l));
                md = (MessageDigest) mds;
                b = mds.getBlockLength() / 8;
            } catch (UnsupportedOperationException e) {
                try {
                    md = MessageDigest.getInstance(alg);
                    b = 512;
                } catch (NoSuchAlgorithmException ex) {
                    throw new InvalidAlgorithmParameterException(ex);
                }
            }
        } else {
            b = 512;
        }
        
        byte[] e = spec.getEncoded();
        md.reset();
        if ( e.length > b) {
            e = md.digest(e);
        }
        
        k_ipad = new byte[b];
        k_opad = new byte[b];

        System.arraycopy(e, 0, k_ipad, 0, e.length);
        System.arraycopy(e, 0, k_opad, 0, e.length);

        for (int i = 0; i < b; i++) {
            k_ipad[i] ^= 0x36;
            k_opad[i] ^= 0x5c;
        }
        md.update(k_ipad);
    }

    @Override
    protected int engineGetMacLength() {
        return md.getDigestLength();
    }

    @Override
    protected void engineUpdate(byte b) {
        md.update(b);
    }

    @Override
    protected void engineUpdate(byte[] bytes, int offset, int len) {
        md.update(bytes, offset, len);
    }

    @Override
    protected byte[] engineDoFinal() {
        byte[] m = md.digest();
        md.update(k_opad);
        byte[] r = md.digest(m);
        md.update(k_ipad);
        return r;
    }

    @Override
    protected void engineReset() {
        md.reset();
        md.digest(k_ipad);
    }
    
}
