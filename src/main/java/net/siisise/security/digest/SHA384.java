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
package net.siisise.security.digest;

/**
 * RFC 6234 SHA-2
 */
public class SHA384 extends SHA512 {

    public static final String OBJECTIDENTIFIER = "2.16.840.1.101.3.4.2.2";

    static final long[] IV384 = {
        0xcbbb9d5dc1059ed8l,
        0x629a292a367cd507l,
        0x9159015a3070dd17l,
        0x152fecd8f70e5939l,
        0x67332667ffc00b31l,
        0x8eb44a8768581511l,
        0xdb0c2e0d64f98fa7l,
        0x47b5481dbefa4fa4l
    };

    public SHA384() {
        super("SHA-384", 384, IV384);
    }
}
