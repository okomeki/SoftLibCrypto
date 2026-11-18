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
package net.siisise.security.key;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import net.siisise.lang.Bin;
import net.siisise.security.block.Blowfish;

/**
 *
 */
public class BCrypt implements KDF {
    
    private static final int[] CTEXT = Bin.btoi("OrpheanBeholderScryDoubt".getBytes(StandardCharsets.UTF_8));
    int cost = 12;
    byte[] salt;
    int len = 23;
    
    public BCrypt(int cost) {
        this.cost = cost;
    }
    
    public void init(int cost, byte[] salt, int len) {
        this.cost = cost;
        this.salt = salt.clone();
        this.len = len;
    }

    /**
     * UTF-8
     */
    @Override
    public byte[] kdf(byte[] password) {
        return kdf(password, len);
    }

    @Override
    public byte[] kdf(byte[] password, int len) {
        
        Blowfish fish = eksBlowfishSetup(cost, salt, password);
        int[] itext = CTEXT;
        for (int i = 0; i < 64; i++) {
            itext = fish.encrypt(itext);
        }
        return Arrays.copyOf(Bin.itob(itext), 23);
    }
    
    Blowfish eksBlowfishSetup(int cost, byte[] salt, byte[] password) {
        Blowfish fish = new Blowfish();
        byte[] passz = Arrays.copyOf(password, password.length + 1);
        
        fish.initBcrypt(cost, salt, passz);
        return fish;
    }
    
}
