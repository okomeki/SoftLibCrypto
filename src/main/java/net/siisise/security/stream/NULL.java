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
package net.siisise.security.stream;

/**
 * NULL 暗号
 */
public class NULL {

    int length;

    NULL() {
        length = 8;
    }

    NULL(int length) {
        this.length = length;
    }

    public int getBlockLength() {
        return length;
    }

    public void init(byte[] key) {
    }

    public byte[] encrypt(byte[] src, int offset) {
        byte[] d = new byte[1];
        d[0] = src[0];
        return d;
    }

    public byte[] decrypt(byte[] src, int offset) {
        byte[] d = new byte[1];
        d[0] = src[0];
        return d;
    }

}
