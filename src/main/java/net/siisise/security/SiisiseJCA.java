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
package net.siisise.security;

import java.security.Provider;
import java.util.ArrayList;
import java.util.List;
import net.siisise.security.digest.Keccak;
import net.siisise.security.digest.MD2;
import net.siisise.security.digest.MD4;
import net.siisise.security.digest.MD5;
import net.siisise.security.digest.SHA1;
import net.siisise.security.digest.SHA224;
import net.siisise.security.digest.SHA256;
import net.siisise.security.digest.SHA3224;
import net.siisise.security.digest.SHA3256;
import net.siisise.security.digest.SHA3384;
import net.siisise.security.digest.SHA3512;
import net.siisise.security.digest.SHA384;
import net.siisise.security.digest.SHA512;
import net.siisise.security.digest.SHA512224;
import net.siisise.security.digest.SHA512256;
import net.siisise.security.digest.SHAKE128;
import net.siisise.security.digest.SHAKE256;
import net.siisise.security.mac.HMACSpi;

/**
 *
 */
public final class SiisiseJCA extends Provider {

    public SiisiseJCA() {
        super("siisise", 0.1, "SiisiseNet Provider v0.1, MD2, MD4, MD5, SHA-1, SHA-2, SHA-3 MessageDigesthash");
        List<String> aliases;
        putService(new Service(this, "MessageDigest", "MD2", MD2.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "MD4", MD4.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "MD5", MD5.class.getName(), null, null));
        aliases = new ArrayList();
        aliases.add("SHA1");
        putService(new Service(this, "MessageDigest", "SHA-1", SHA1.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("SHA-2-224");
        putService(new Service(this, "MessageDigest", "SHA-224", SHA224.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("SHA-2-256");
        putService(new Service(this, "MessageDigest", "SHA-256", SHA256.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("SHA-2-384");
        putService(new Service(this, "MessageDigest", "SHA-384", SHA384.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("SHA-2-512");
        putService(new Service(this, "MessageDigest", "SHA-512", SHA512.class.getName(), aliases, null));
        putService(new Service(this, "MessageDigest", "SHA-512/224", SHA512224.class.getName(), null, null) {
            @Override
            public SHA512 newInstance(Object cp) {
                return new SHA512(224);
            }
        });
        putService(new Service(this, "MessageDigest", "SHA-512/256", SHA512256.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "Keccak-224", Keccak.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "Keccak-256", Keccak.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "Keccak-384", Keccak.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "Keccak-512", Keccak.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "SHA3-224", SHA3224.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "SHA3-256", SHA3256.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "SHA3-384", SHA3384.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "SHA3-512", SHA3512.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "SHAKE128-128", SHAKE128.class.getName(), null, null));
        putService(new Service(this, "MessageDigest", "SHAKE128-256", SHAKE256.class.getName(), null, null));
        aliases = new ArrayList();
        aliases.add("HMAC-MD5");
        aliases = null;
        putService(new Service(this, "Mac", "HmacMD5", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        //ToDo: HMACParameterSpec を使う
        aliases.add("HMAC-MD5-96");
        aliases = null;
        putService(new Service(this, "Mac", "HmacMD5-96", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA1");
        aliases.add("HMAC-SHA-1");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA1", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        //ToDo: HMACParameterSpec を使う
        aliases.add("HMAC-SHA1-96");
        aliases.add("HMAC-SHA-1-96");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA1-96", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA-224");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA224", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA-256");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA256", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA-384");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA384", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA-512");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA512", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA-512/224");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA512/224", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA-512/256");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA512/256", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA3-224");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA3-224", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA3-256");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA3-256", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA3-384");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA3-384", HMACSpi.class.getName(), aliases, null));
        aliases = new ArrayList();
        aliases.add("HMAC-SHA3-512");
        aliases = null;
        putService(new Service(this, "Mac", "HmacSHA3-512", HMACSpi.class.getName(), aliases, null));
    }

}
