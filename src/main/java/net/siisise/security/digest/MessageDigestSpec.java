package net.siisise.security.digest;

import java.lang.reflect.InvocationTargetException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * HMACで使用するblockLengthがほしい.
 * 
 */
public interface MessageDigestSpec {

    /**
     * ブロック長
     * @return ビット長
     */
    int getBlockLength();

    static MessageDigestSpec getInstance(String alg) {
        MessageDigestSpec md;
            try {
                alg = alg.toUpperCase();
                if (alg.startsWith("SHA3-")) {
                    md = new SHA3(Integer.parseInt(alg.substring(5)));
                } else if (alg.startsWith("SHA-512/")) { // HMACで可変仕様の存在は知らない
                    md = new SHA512(Integer.parseInt(alg.substring(8)));
                } else if (alg.startsWith("SHA512/")) { // HMACで可変仕様の存在は知らない
                    md = new SHA512(Integer.parseInt(alg.substring(7)));
                } else if (alg.startsWith("SHA-1-")) {
                    md = new SHA1(Integer.parseInt(alg.substring(6)));
                } else if (alg.startsWith("SHA1-")) {
                    md = new SHA1(Integer.parseInt(alg.substring(5)));
                } else if (alg.startsWith("MD5-")) {
                    md = new MD5(Integer.parseInt(alg.substring(4)));
                } else {
                    String digestName = alg.replaceAll("[\\/\\-]", "");
                    md = (MessageDigestSpec) Class.forName("net.siisise.security.digest." + digestName).getConstructor().newInstance();
                }
                return md;
            } catch (ClassNotFoundException ex) {
                Logger.getLogger(MessageDigestSpec.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InstantiationException ex) {
                Logger.getLogger(MessageDigestSpec.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalAccessException ex) {
                Logger.getLogger(MessageDigestSpec.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalArgumentException ex) {
                Logger.getLogger(MessageDigestSpec.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvocationTargetException ex) {
                Logger.getLogger(MessageDigestSpec.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchMethodException ex) {
                Logger.getLogger(MessageDigestSpec.class.getName()).log(Level.SEVERE, null, ex);
            } catch (SecurityException ex) {
                Logger.getLogger(MessageDigestSpec.class.getName()).log(Level.SEVERE, null, ex);
            }
            throw new UnsupportedOperationException();
    }
}
