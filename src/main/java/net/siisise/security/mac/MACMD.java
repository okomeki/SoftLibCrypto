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
package net.siisise.security.mac;

import net.siisise.security.digest.BlockMessageDigest;

/**
 * MAC を MDっぽく扱ってもいいのでは.
 */
public class MACMD extends BlockMessageDigest {

    final MAC mac;

    public MACMD(MAC mac, String name) {
        super(name);
        this.mac = mac;
    }
    
    /**
     * パラメータ変更などもできるのかも.
     * @return 中のMAC.
     */
    public MAC getMAC() {
        return mac;
    }

    @Override
    protected byte[] engineDigest() {
        return mac.doFinal();
    }

    /**
     * 計算すれば元に戻るよ.
     * 各種MAC用パラメータは保持する.
     */
    @Override
    protected void engineReset() {
        mac.doFinal();
    }

    @Override
    public void blockWrite(byte[] src, int offset, int length) {
        mac.update(src, offset, length);
    }

    @Override
    public int getBitBlockLength() {
        return mac.getMacLength() * 8;
    }
}
