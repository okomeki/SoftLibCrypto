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

import net.siisise.security.sign.EdDSA;

/**
 * EdDSAの公開鍵.
 */
public class EdDSAPublicKey {
    EdDSA.EllipticCurve curve;
    byte[] A;

    public EdDSAPublicKey(EdDSA.EllipticCurve curve, byte[] A) {
        this.curve = curve;
        this.A = A;
    }
    
    public EdDSA.EllipticCurve getCurve() {
        return curve;
    }
    
    public byte[] getA() {
        return A.clone();
    }
}
