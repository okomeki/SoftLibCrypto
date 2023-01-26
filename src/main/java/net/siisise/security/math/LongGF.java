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
package net.siisise.security.math;

import java.math.BigInteger;
import net.siisise.security.block.AES;

/**
 * ガロア体.
 * 長ビット対応版
 */
public class LongGF {
    
    /**
     * ビット長.
     */
    final int N;
    final long[] root;

    public LongGF(int n, long m) {
        this(n, new long[] {m});
    }
    
    /**
     * 
     * @param n 2^n ビット長
     * @param m 
     */
    public LongGF(int n, long[] m) {
        N = n - 1;
        root = m;
//        size = (1 << n) - 1; 
    }

    public final int x(long[] a) {
        long[] b = new long[a.length];
        for ( int i = 0; i < a.length - 1; i++ ) {
            b[i] = (a[i] << 1) | (a[i+1] >>> 63);
        }
        b[a.length-1] = (a[a.length - 1] << 1);
        
        BigInteger bb = new BigInteger(AES.ltob(b));
/*
        bb
        
        
        for ( int i = 0; i < ^ ((a[0] >>> (N % 64)) * root);
        return (a << 1) ^ ((a >>> N) * root); 
        return x[a];
*/
        throw new UnsupportedOperationException();
    }
}
