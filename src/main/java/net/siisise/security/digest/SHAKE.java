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
package net.siisise.security.digest;

/**
 * SHAKE128 / SHAKE256.
 * FIPS PUB 202
 */
public class SHAKE extends Keccak implements XOF {
    
    /**
     * 
     * @param c 128 または 256
     * @param d 出力長
     */
    public SHAKE(int c, long d) {
        super("SHAKE" + c, c*2, d, (byte)0x1f);
    }

    /**
     * 固定長出力.
     * @param c 128 または 256
     */
    public SHAKE(int c) {
        this(c, c*2);
    }
}
