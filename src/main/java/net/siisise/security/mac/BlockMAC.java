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
package net.siisise.security.mac;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.siisise.security.io.BlockIOListener;
import net.siisise.security.io.BlockIOOutputStream;

/**
 * Block系をもっていないときになんとかする
 * CMACか?
 */
public abstract class BlockMAC implements MAC,BlockIOListener {
    
    BlockIOOutputStream pac;

    @Override
    public void init(byte[] key) {
        pac = new BlockIOOutputStream(this);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        try {
            pac.write(src, offset, length);
        } catch (IOException ex) {
            Logger.getLogger(BlockMAC.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public byte[] doFinal() {
        try {
            pac.close();
        } catch (IOException ex) {
            Logger.getLogger(BlockMAC.class.getName()).log(Level.SEVERE, null, ex);
        }
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getMacLength() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    // listener
    
    @Override
    public int getBitBlockLength() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void flush() throws IOException {
    }

    @Override
    public void close() throws IOException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
