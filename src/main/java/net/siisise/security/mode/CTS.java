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
package net.siisise.security.mode;

import net.siisise.security.block.Block;

/**
 * RFC 2040
 * @deprecated まだ
 */
@Deprecated
public class CTS extends CBC {

    private int len;

    public CTS(Block block) {
        super(block);
        len = block.getBlockLength();
    }

    @Override
    public byte[] doFinalEncrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }

    @Override
    public byte[] doFinalDecrypt(byte[] src, int offset, int length) {
        int bl = length / len;

        byte[] ret = new byte[length];
        int off = 0;
        if ( bl > 0 ) {
            System.arraycopy(decrypt(src, offset, bl * len), 0, ret, 0, bl * len);
            off = bl * len;
        }
        
        return decrypt(src, offset, length);
    }
}
