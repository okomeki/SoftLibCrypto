/*
 * Copyright 2026 okome.
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
package net.siisise.security.key.mcf;

import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import net.siisise.io.BASE64;
import net.siisise.security.block.DES;

/**
 * DES-Crypt.
 * DESでパスワード管理する初期.
 * [./0-9A-Za-z]
 * 2文字 12 bit integer salt
 *
 * @deprecated 廃止暗号
 */
@Deprecated
public class DEScrypt implements ModularCryptFormat {

    /**
     * MCF生成.
     *
     * @param pass パスワード
     * @return MCF
     */
    @Override
    public String generate(String pass) {

        // 2文字作れれば何でもいい
        BASE64 ble = new BASE64.LE(BASE64.PASSWORD, 0);

        String salt;
        // 12 bit salt 2char
        try {
            byte[] saltsrc = SecureRandom.getInstanceStrong().generateSeed(2);
            salt = ble.encode(saltsrc).substring(0, 2);
        } catch (NoSuchAlgorithmException ex) {
            // ない
            throw new IllegalStateException(ex);
        }
        return encode(salt, pass);
    }

    /**
     * MCF生成.
     *
     * @param salt 2文字
     * @param pass 8文字までのパスワード
     * @return 13文字
     */
    String encode(String salt, String pass) {

        byte[] passcode = pass.getBytes(StandardCharsets.UTF_8);
        // key
        byte[] bin = new byte[8];
        DES des = new DES();
        System.arraycopy(passcode, 0, bin, 0, Math.min(passcode.length, 8));
        des.init(bin);
        BASE64 b64 = new BASE64(BASE64.Type.PASSWORD, false, 0); // hash64
        BASE64 ble = new BASE64.LE(BASE64.Type.PASSWORD, false, 0);
        byte[] saltbin = new byte[salt.length()];
        for (int i = 0; i < saltbin.length; i++) {
            byte[] dec = ble.decode(salt.substring(i, i + 1) + ".");
            saltbin[i] = dec[0];
        }
        des.setSalt(saltbin);

        Arrays.fill(bin, (byte) 0);
        for (int i = 0; i < 25; i++) {
            bin = des.encrypt(bin);
        }
        return salt + b64.encode(bin);
    }

    @Override
    public boolean verify(String pass, String code) {
        String salt = code.substring(0, code.length() - 11);
        return code.equals(encode(salt, pass));
    }
}
