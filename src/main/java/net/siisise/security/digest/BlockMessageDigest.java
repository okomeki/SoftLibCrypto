/*
 * Copyright 2023 Siisise Net.
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
            } else if (alg.startsWith("SHAKE")) {
                md = new SHAKE(Integer.parseInt(alg.substring(5)));
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
