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
package net.siisise.security.key;

import java.security.NoSuchAlgorithmException;

/**
 * bcrypt の適当な実装.
 * 文字コードはUTF-8まで想定する. $2a$
 * opensshで使われていたりするのでつついておく.
 * 
 * @deprecated net.siisise.security.key.mcf.BCrypt MCFでまとめたので移行
 */
@Deprecated
public class BCrypt {

    private final net.siisise.security.key.mcf.BCrypt bf;
    
    public BCrypt() {
        bf = new net.siisise.security.key.mcf.BCrypt();
    }

    /**
     * 生成用.
     * saltを中で作る.
     * @param cost 繰り返しのビット数 1&lt;&lt;cost 4..31
     * @param pass UTF-8パスワード 1 から 72バイト
     * @return hash
     * @throws NoSuchAlgorithmException 
     */
    public String gen(int cost, String pass) throws NoSuchAlgorithmException {
        return bf.gen(cost, pass);
    }
    
    /**
     * 生成/照合用.
     * @param cost 繰り返しのビット数 1&lt;&lt;cost 4..31
     * @param salt 16byte 乱数
     * @param pass UTF-8パスワード 1 から 72バイト
     * @return 
     */
    public String encode(int cost, byte[] salt, String pass) {
        return bf.encode(cost, salt, pass);
    }

    public boolean veryfy(String pass, String code) {
        return bf.verify(pass, code);
    }
}
