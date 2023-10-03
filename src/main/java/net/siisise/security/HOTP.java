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
package net.siisise.security;

import java.math.BigInteger;
import net.siisise.security.digest.SHA1;
import net.siisise.security.mac.HMAC;

/**
 * RFC 4226 HOTP
 */
public class HOTP implements OTP {
    HMAC hmac;
    
    byte[] K;
    
    int Digit = 6;
    
    /**
     * Section 5.2.
     * @param key K
     * @param counter C
     */
    int hotp(byte[] key, byte[] counter) {
        hmac = new HMAC(new SHA1(), key);
        byte[] hs = hmac.doFinal(counter);
        byte[] Sbits = DT(hs);
        int Snum = StToNum(Sbits); // Convert S to a number in
                                           // 0...2^{31}-1
        return Snum % (10^Digit);
        
//        hs = Truncate(hs);
        
    }
    
    byte[] DT(byte[] hs) {
        throw new UnsupportedOperationException();
    }
    
    int StToNum(byte[] sbits) {
        BigInteger num = new BigInteger(sbits);
        return num.intValue();
    }

    /**
     * Section 5.3.
     * @param hs
     * @return 
     */    
    byte[] Truncate(byte[] hs) {
        throw new UnsupportedOperationException();
    }
    
}
