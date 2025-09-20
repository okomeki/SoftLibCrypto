/*
 * Copyright 2025 okome.
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
package net.siisise.security.key;

import java.security.PublicKey;
import net.siisise.security.ec.EdWards;
import net.siisise.security.ec.EdWards25519;
import net.siisise.security.ec.EdWards448;

/**
 * EdDSAの公開鍵.
 * JDKの対応は15以降ぐらい
 */
public class EdDSAPublicKey implements PublicKey {
    EdWards curve;
    byte[] A;

    public EdDSAPublicKey(EdWards curve, byte[] A) {
        this.curve = curve;
        this.A = A;
    }
    
    public EdWards getCurve() {
        return curve;
    }

    /**
     * 公開鍵.
     * @return 公開鍵 
     */
    public byte[] getA() {
        return A.clone();
    }

    @Override
    public String getAlgorithm() {
        if ( curve instanceof EdWards25519) {
            return "Ed25519";
        } else if (curve instanceof EdWards448) {
            return "Ed448";
        }
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public String getFormat() {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] getEncoded() {
        return A.clone();
    }
}
