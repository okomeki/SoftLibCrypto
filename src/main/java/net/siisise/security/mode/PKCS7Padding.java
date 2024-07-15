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
package net.siisise.security.mode;

import java.util.Arrays;
import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.lang.Bin;
import net.siisise.security.block.Block;

/**
 * PKCS #7 らしい Padding.
 * 繰り返しは想定していない.
 */
public class PKCS7Padding extends BlockMode {

    private int blockLength;
    private final Packet encBuffer = new PacketA();
    private final Packet decBuffer = new PacketA();

    public PKCS7Padding(Block block) {
        super(block);
        blockLength = (block.getBlockLength() + 7) / 8;
    }

    @Override
    public int[] getParamLength() {
        return block.getParamLength();
    }

    @Override
    public int getBlockLength() {
        blockLength = block.getBlockLength() / 8;
        return blockLength * 8;
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        encBuffer.write(src, offset, length);
        return encOut();
    }
    
    private byte[] encOut() {
        int s = encBuffer.size();
        int bs = s / blockLength;
        if (bs == 0) {
            return new byte[0];
        }
        byte[] data = new byte[bs * blockLength];
        encBuffer.read(data);
        return block.encrypt(data, 0, data.length);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        decBuffer.write(src, offset, length);
        return decOut();
    }

    /**
     * 1block 残す.
     * @return 
     */
    private byte[] decOut() {
        int s = decBuffer.size() - 1;
        int bs = s / blockLength;
        if (bs == 0) {
            return new byte[0];
        }
        byte[] data = new byte[bs * blockLength];
        decBuffer.read(data);
        return block.decrypt(data, 0, data.length);
    }


    @Override
    public int[] encrypt(int[] src, int offset, int length) {
        encBuffer.write(Bin.itob(src, offset, length));
        return Bin.btoi(encOut());
    }

    @Override
    public int[] decrypt(int[] src, int offset, int length) {
        decBuffer.write(Bin.itob(src, offset, length));
        return Bin.btoi(decOut());
    }

    @Override
    public long[] encrypt(long[] src, int offset, int length) {
        encBuffer.write(Bin.ltob(src,offset,length));
        return Bin.btol(encOut());
    }

    @Override
    public long[] decrypt(long[] src, int offset, int length) {
        decBuffer.write(Bin.ltob(src,offset,length));
        return Bin.btol(decOut());
    }

    /**
     * 使える?
     * @param src
     * @param offset
     * @param dst
     * @param doffset
     * @param length
     * @deprecated バッファするとサイズが変わるので使えないかもしれない
     */
    @Override
    @Deprecated
    public void encrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        encBuffer.write(src, offset, length);
        int s = encBuffer.size();
        int bs = s / blockLength;
        byte[] data = new byte[bs * blockLength];
        encBuffer.read(data);
        block.encrypt(data, 0, dst, doffset, data.length);
    }

    @Override
    @Deprecated
    public void decrypt(byte[] src, int offset, byte[] dst, int doffset, int length) {
        decBuffer.write(src, offset, length);
        int s = decBuffer.size();
        int bs = s / blockLength;
        byte[] data = new byte[bs * blockLength];
        decBuffer.read(data);
        block.decrypt(data, 0, dst, doffset, data.length);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        return block.encrypt(src, offset);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return block.decrypt(src, offset);
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        return block.encrypt(src, offset);
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        return block.decrypt(src, offset);
    }

    @Override
    public long[] encrypt(long[] src, int offset) {
        return block.encrypt(src, offset);
    }

    @Override
    public long[] decrypt(long[] src, int offset) {
        return block.decrypt(src, offset);
    }

    @Override
    public byte[] doFinalEncrypt(byte[] src, int offset, int length) {
        Packet enc = new PacketA();
        enc.write(encrypt(src, offset, length));
        byte[] encBlock = new byte[blockLength];
        int len = encBuffer.read(encBlock);
        if ( encBlock.length > len ) {
            Arrays.fill(encBlock, len, encBlock.length, (byte)(blockLength - len));
            enc.write(block.encrypt(encBlock, 0, blockLength));
        } else {
            enc.write(block.encrypt(encBlock, 0, blockLength));
            Arrays.fill(encBlock, (byte)blockLength);
            enc.write(block.encrypt(encBlock, 0, blockLength));
            throw new IllegalStateException();
        }
        return enc.toByteArray();
    }

    @Override
    public byte[] doFinalDecrypt(byte[] src, int offset, int length) {
        Packet dec = new PacketA();
        dec.write(decrypt(src, offset, length));
        
        byte[] decBlock = new byte[blockLength];
        int len = decBuffer.read(decBlock);
        if ( decBlock.length > len ) {
            throw new IllegalStateException();
        } else {
            decBlock = block.decrypt(decBlock, 0, decBlock.length);
            byte l = decBlock[len -1];
            len = ((int)l) & 0xff;
            for ( int i = decBlock.length - len; i < decBlock.length; i++) {
                if ( decBlock[i] != l) {
                    throw new IllegalStateException();
                }
            }
            dec.write(decBlock, 0, decBlock.length - len);
        }
        return dec.toByteArray();
    }
}
