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
package net.siisise.security.key;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.RSAMultiPrimePrivateCrtKeySpec;
import java.security.spec.RSAOtherPrimeInfo;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 *
 */
public class SoftLibKeyFactorySpi extends KeyFactorySpi {

    /**
     * CRT以上のPrivateKeyでも作れる.
     * @param keySpec PublicKeySpec または RSAPrivateCrtKeySpec以上
     * @return
     * @throws InvalidKeySpecException 
     */
    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if ( keySpec instanceof RSAMultiPrimePrivateCrtKeySpec ) {
            RSAMultiPrimePrivateCrtKeySpec k = (RSAMultiPrimePrivateCrtKeySpec)keySpec;
            return new RSAPublicKey(k.getModulus(), k.getPublicExponent());
        } else if ( keySpec instanceof RSAPrivateCrtKeySpec) {
            RSAPrivateCrtKeySpec k = (RSAPrivateCrtKeySpec)keySpec;
            return new RSAPublicKey(k.getModulus(), k.getPublicExponent());
        } else if ( keySpec instanceof RSAPublicKeySpec ) {
            RSAPublicKeySpec k = (RSAPublicKeySpec)keySpec;
            return new RSAPublicKey(k.getModulus(), k.getPublicExponent());
        }
        throw new InvalidKeySpecException();
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if ( keySpec instanceof RSAPrivateCrtKeySpec ) {
            RSAPrivateCrtKeySpec spec = (RSAPrivateCrtKeySpec)keySpec;
            RSAPrivateCrtKey key = new RSAPrivateCrtKey(
                    spec.getModulus(),
                    spec.getPublicExponent(),
                    spec.getPrivateExponent(),
                    spec.getPrimeP(),
                    spec.getPrimeQ(),
                    spec.getPrimeExponentP(),
                    spec.getPrimeExponentQ(),
                    spec.getCrtCoefficient()
            );
            key.version = 0;
            if ( !RSAKeyGen.validate(key) ) {
                throw new InvalidKeySpecException();
            }
            return key;
        } else if ( keySpec instanceof RSAPrivateKeySpec ) {
            RSAPrivateKeySpec spec = (RSAPrivateKeySpec)keySpec;
            return new RSAMiniPrivateKey(spec.getModulus(), spec.getPrivateExponent());
        }
        throw new InvalidKeySpecException();
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        if ( key instanceof RSAMultiPrivateKey ) {
            if ( keySpec == RSAMultiPrimePrivateCrtKeySpec.class ) {
                RSAMultiPrivateKey.OtherPrimeInfo[] sothers = ((RSAMultiPrivateKey) key).otherPrimeInfos;
                RSAOtherPrimeInfo[] others = new RSAOtherPrimeInfo[sothers.length];
                for ( int i = 0; i < sothers.length; i++) {
                    others[i] = new RSAOtherPrimeInfo(sothers[i].prime, sothers[i].exponent, sothers[i].coefficient);
                }
                return (T) new RSAMultiPrimePrivateCrtKeySpec(((RSAMultiPrivateKey) key).getModulus(),
                        ((RSAMultiPrivateKey) key).getPublicExponent(),
                        ((RSAMultiPrivateKey) key).getPrivateExponent(),
                        ((RSAMultiPrivateKey) key).getPrimeP(),
                        ((RSAMultiPrivateKey) key).getPrimeQ(),
                        ((RSAMultiPrivateKey) key).getPrimeExponentP(),
                        ((RSAMultiPrivateKey) key).getPrimeExponentQ(),
                        ((RSAMultiPrivateKey) key).getCrtCoefficient(),
                        others
                );
            }
            throw new SecurityException();
        } else if ( key instanceof RSAPrivateCrtKey ) {
            if ( keySpec == RSAPrivateCrtKeySpec.class ) {
                return (T) new RSAPrivateCrtKeySpec(((RSAPrivateCrtKey) key).getModulus(),
                        ((RSAPrivateCrtKey) key).getPublicExponent(),
                        ((RSAPrivateCrtKey) key).getPrivateExponent(),
                        ((RSAPrivateCrtKey) key).getPrimeP(),
                        ((RSAPrivateCrtKey) key).getPrimeQ(),
                        ((RSAPrivateCrtKey) key).getPrimeExponentP(),
                        ((RSAPrivateCrtKey) key).getPrimeExponentQ(),
                        ((RSAPrivateCrtKey) key).getCrtCoefficient()
                );
            }
        }
        if ( key instanceof RSAPrivateKey ) {
            if ( keySpec == RSAPrivateKeySpec.class ) {
                return (T)new RSAPrivateKeySpec(((RSAPrivateCrtKey) key).getModulus(), ((RSAPrivateCrtKey) key).getPrivateExponent());
            }
        }
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        throw new UnsupportedOperationException("Not supported yet.");
    }
    
}
