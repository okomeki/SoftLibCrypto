/*
 * Copyright 2022 Siisise Net.
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

import net.siisise.security.sign.SignVerify;

/**
 * Message Authentication Code
 * Mac のどこでも使える版
 */
public interface MAC extends SignVerify {

    void init(byte[] key);
    
    default byte[] doFinal(byte[] src) {
        update(src);
        return sign();
    }
    
    default byte[] doFinal() {
        return sign();
    }

    /**
     * バイト単位の出力長
     *
     * @return バイト長
     */
    int getMacLength();
    
    /**
     * 鍵生成用長さ.
     * @return 鍵バイト長
     */
    @Override
    default int getKeyLength() {
        return getMacLength();
    }
}
