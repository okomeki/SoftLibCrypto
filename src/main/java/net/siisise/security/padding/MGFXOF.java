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
package net.siisise.security.padding;

import net.siisise.security.digest.XOF;

/**
 * XOFをMGFに変換するだけ.
 * RFC 8702
 * SHAKE128 d = 256
 * SHAKE256 d = 512
 */
public class MGFXOF implements MGF {

    // 型は仮
    private final XOF xof;
    
    /**
     * 
     * @param xof XOF関数
     */
    public MGFXOF(XOF xof) {
        this.xof = xof;
    }

    /**
     * XOFの出力.
     * 併用している場合もあるので元の設定を維持する.
     * @param seed
     * @param maskLen octet
     * @return 
     */
    @Override
    public byte[] generate(byte[] seed, long maskLen) {
        long org = xof.getBitDigestLength();
        xof.setDigestLength((int)maskLen);
        byte[] digest = xof.digest(seed);
        xof.setBitDigestLength(org);
        return digest;
    }
    
}
