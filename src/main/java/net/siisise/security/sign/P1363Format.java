/*
 * Copyright 2026 okome.
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
package net.siisise.security.sign;

import java.math.BigInteger;
import java.util.Collection;
import java.util.Map;
import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;
import net.siisise.ietf.pkcs1.PKCS1;

/**
 * IEEE P1363
 */
public class P1363Format implements TypeFormat<byte[]> {

    /**
     * バイト長
     */
    int bsize;

    /**
     * 
     * @param blen ビット長
     */
    public P1363Format(int blen) {
        bsize = (blen + 7) / 8;
    }

    @Override
    public byte[] nullFormat() {
        return null;
    }

    @Override
    public byte[] booleanFormat(boolean bool) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] numberFormat(Number num) {
        if (!(num instanceof BigInteger)) {
            num = Rebind.valueOf(num, BigInteger.class);
        }
        return PKCS1.I2OSP((BigInteger)num, bsize);
    }

    @Override
    public byte[] stringFormat(String str) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public byte[] mapFormat(Map map) {
        int size = map.size();
        byte[] tmp = new byte[bsize * size];
        Map<?, Object> m = map;
        Collection<Object> v = m.values();
        Object[] s = v.stream().map(n -> Rebind.valueOf(n, this)).toArray();
        for (int i = 0; i < s.length; i++) {
            System.arraycopy((byte[]) s[i], 0, tmp, bsize * i, bsize);
        }
        return tmp;
    }

    @Override
    public byte[] collectionFormat(Collection col) {
        int size = col.size();
        Collection<Object> v = col;
        byte[] tmp = new byte[bsize * size];
        Object[] s = v.stream().map(n -> Rebind.valueOf(n, this)).toArray();
        for (int i = 0; i < s.length; i++) {
            System.arraycopy((byte[]) s[i], 0, tmp, bsize * i, bsize);
        }
        return tmp;
    }

}
