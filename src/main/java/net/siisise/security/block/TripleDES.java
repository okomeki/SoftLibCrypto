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
package net.siisise.security.block;

import net.siisise.iso.asn1.tag.OBJECTIDENTIFIER;

/**
 * 3DES. TDEA DESede.
 * とある暗号アルゴリズム.
 * DESede ともいう
 * ANSI X9.52-1998
 * @deprecated AES
 */
@Deprecated
public class TripleDES extends OneBlock {
    
    public static final OBJECTIDENTIFIER desEDE3_CBC = encryptionAlgorithm.sub(7);
    // パラメータ OCTETSTRING(SIZE(8))

    private DES block1;
    private DES block2;
    private DES block3;
    
    public TripleDES() {
        block1 = new DES();
        block2 = new DES();
        block3 = new DES();
    }
    
    public void init(byte[] key) {
        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        byte[] k3 = new byte[8];

        switch ( key.length ) {
            case 8:
                System.arraycopy(key, 0, k1, 0, 8);
                init(k1,k1);
                break;
            case 16:
                System.arraycopy(key, 0, k1, 0, 8);
                System.arraycopy(key, 8, k2, 0, 8);
                init(k1,k2);
                break;
            case 24:
                System.arraycopy(key, 0, k1, 0, 8);
                System.arraycopy(key, 8, k2, 0, 8);
                System.arraycopy(key, 16, k3, 0, 8);
                init(k1,k2,k3);
                break;
            default:
                throw new UnsupportedOperationException();
        }
    }

    /**
     * 鍵2個でとりぷるDES。
     * @param keys 鍵1 1回目と3回目に使用する。 鍵2 2回目に使用する。
     */
    @Override
    public void init(byte[]... keys) {
        block1 = new DES();
        block2 = new DES();
        block3 = new DES();
        switch (keys.length) {
            case 1:
                init(keys[0]);
                break;
            case 2:
                block1.init(keys[0]);
                block2.init(keys[1]);
                block3.init(keys[0]);
                break;
            case 3:
                block1.init(keys[0]);
                block2.init(keys[1]);
                block3.init(keys[2]);
                break;
            default:
                break;
        }
    }

    /**
     * プロック長.
     * @return ブロック長 64bit
     */
    @Override
    public int getBlockLength() {
        return block1.getBlockLength();
    }
    
    /**
     * 鍵長.
     * DESブロック長の3倍
     * @return 192bit
     */
    @Override
    public int[] getParamLength() {
        return new int[] {getBlockLength() * 3};
    }
    
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        return block1.encrypt(block2.decrypt(block3.encrypt(src, offset),0),0);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return block3.decrypt(block2.encrypt(block1.decrypt(src, offset),0),0);
    }
}
