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
package net.siisise.security.mode;

import net.siisise.lang.Bin;
import net.siisise.security.block.Block;
import net.siisise.security.mac.MAC;

/**
 *
 */
public class BlockAEAD extends LongBlockMode implements StreamAEAD {
    private MAC mac;
    int blockLength;
    /**
     * 
     * @param block ブロック暗号 AES/CBC など
     * @param mac ハッシュ HMAC など
     */
    public BlockAEAD(Block block, MAC mac) {
        super(block);
        this.mac = mac;
        blockLength = block.getBlockLength() / 8;
    }

    /**
     * 
     * @param params mac鍵、aad, mode iv, block鍵 の順?
     */
    @Override
    public void init(byte[]... params) {
       mac.init(params[0]);
       int p = 1;
       if ( params.length > 3) {
           mac.update(params[1]);
           p++;
       }
       block.init(in(p,params));
    }
    
    @Override
    public long[] encrypt(long[] src, int offset) {
        long[] c = block.encrypt(src, offset);
        mac.update(Bin.ltob(c), 0, blockLength);
        return c;
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        byte[] c = block.encrypt(src, offset);
        mac.update(c, 0, blockLength);
        return c;
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        mac.update(Bin.ltob(src), 0, blockLength);
        return block.decrypt(src, offset);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        mac.update(src, 0, blockLength);
        return block.decrypt(src, offset);
    }

    @Override
    public byte[] tag() {
        return mac.sign();
    }

    @Override
    public byte[] doFinalEncrypt(byte[] src, int offset, int length) {
        encrypt(src, offset, length);
        return tag();
    }

    @Override
    public byte[] doFinalDecrypt(byte[] src, int offset, int length) {
        encrypt(src, offset, length);
        return tag();
    }

}
