/*
 * Copyright 2023 okome.
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
package net.siisise.security.rng;

import java.time.Instant;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.block.Block;

/**
 * ANSI X9.17 X9.31
 */
public class X917 implements PRNG {
    Block block;
    long[] vector;
    
    public X917(Block block) {
        this.block = block;
        vector = new long[2];
        // 初期値は 0 以外?
        vector[0] = 10;
        vector[1] = 20;
    }

    void init(byte[] iv, byte[] key) {
        vector = Bin.btol(iv);
        block.init(key);
    }
    
    byte[] gen() {
        Instant i = Instant.now();
        long[] t = new long[2]; // 128 bit
        t[0] = i.getEpochSecond();
        t[1] = i.getNano();
        t = block.encrypt(t);
        Bin.xorl(vector, t);
        vector = block.encrypt(vector);
        byte[] r = Bin.ltob(vector);
        Bin.xorl(vector, t);
        block.encrypt(vector);
        return r;
    }
    
    public byte[] nextGen(int len) {
        Packet pac = new PacketA();
        while ( pac.size() < len) {
            pac.write(gen());
        }
        byte[] r = new byte[len];
        pac.read(r);
        return r;
    }
    
}
