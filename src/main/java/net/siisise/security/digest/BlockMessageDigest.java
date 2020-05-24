package net.siisise.security.digest;

import java.lang.reflect.InvocationTargetException;
import java.security.MessageDigest;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.siisise.security.io.BlockListener;
import net.siisise.security.io.BlockOutputStream;

/**
 *
 */
public abstract class BlockMessageDigest extends MessageDigest implements BlockListener {

    protected BlockOutputStream pac;
    protected long length;

    protected BlockMessageDigest(String name) {
        super(name);
//        pac = new BlockOutputStream(getBitBlockLength() / 8, this);
    }

    @Override
    protected void engineUpdate(byte input) {
        engineUpdate(new byte[]{input}, 0, 1);
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        pac.write(input, offset, len);
        length += len * 8l;
    }

    public static BlockMessageDigest getInstance(String alg) {
        BlockMessageDigest md;
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
                md = (BlockMessageDigest) Class.forName("net.siisise.security.digest." + digestName).getConstructor().newInstance();
            }
            return md;
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException | IllegalArgumentException | InvocationTargetException | NoSuchMethodException | SecurityException ex) {
            Logger.getLogger(BlockMessageDigest.class.getName()).log(Level.SEVERE, null, ex);
        }
        throw new UnsupportedOperationException();
    }
    
    @Override
    public void flush() {
        
    }
    
    /**
     * MessageDigestでは doFinal で閉めるので使わない
     * @param buffer
     * @param len
     */
    @Override
    public void blockFlush(byte[] buffer, int len) {
        throw new UnsupportedOperationException();
    }
    
    @Override
    public void close() {
        throw new UnsupportedOperationException();
    }
}
