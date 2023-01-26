/*
 * Copyright 2021 Siisise Net.
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

/**
 * SHA-3系に用意されているらしい標準MAC
 */
public class KMAC implements MAC {

    @Override
    public void init(byte[] key) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] doFinal() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public int getMacLength() {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
