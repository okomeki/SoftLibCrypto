/*
 * Copyright 2024 okome.
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
package net.siisise.security.block;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import net.siisise.lang.Bin;
import net.siisise.security.mode.StreamAEAD;

/**
 * Java AES. Java 標準の暗号を速度比較のためにラップしてみる.
 */
public class CipherWrap extends LongBlock implements StreamAEAD {

    String transformation;
    private Cipher enc;
    private Cipher dec;
    
    /**
     * Java Cipherのラップ.
     * AES/GCM/NoPadding などを指定する.
     * 
     * @param mode 暗号
     */
    public CipherWrap(String mode) {
        transformation = mode;
    }
    
    @Override
    public int getBlockLength() {
        return enc.getBlockSize() * 8;
    }

    /**
     *
     * @param params
     */
    @Override
    public void init(byte[]... params) {
        try {
            byte[] paramkey = params[0];
            enc = Cipher.getInstance(transformation); // AES のみ
            SecretKey key = new SecretKeySpec(paramkey, "AES");
            enc.init(Cipher.ENCRYPT_MODE, key);
            dec = Cipher.getInstance("AES");
            dec.init(Cipher.DECRYPT_MODE, key);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public long[] encrypt(long[] src, int offset) {
        return Bin.btol(enc.update(Bin.ltob(src, offset, 2)));
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        return Bin.btol(dec.update(Bin.ltob(src, offset, 2)));
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        return Bin.btoi(enc.update(Bin.itob(src, offset, 4)));
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        return Bin.btoi(dec.update(Bin.itob(src, offset, 4)));
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        return enc.update(src, offset, 16);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return dec.update(src, offset, 16);
    }
    
    @Override
    public byte[] doFinalEncrypt(byte[] src, int offset, int length) {
        try {
            return enc.doFinal(src, offset, length);
        } catch (IllegalBlockSizeException | BadPaddingException ex) {
            throw new IllegalStateException(ex);
        }
    }

    @Override
    public byte[] tag() {
        return doFinalEncrypt();
    }

    @Override
    public byte[] doFinalDecrypt(byte[] src, int offset, int length) {
        try {
            return dec.doFinal(src, offset, length);
        } catch (IllegalBlockSizeException ex) {
            throw new IllegalStateException(ex);
        } catch (BadPaddingException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
