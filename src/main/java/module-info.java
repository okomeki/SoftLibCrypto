/*
 * Copyright 2024 okome.
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

module net.siisise.crypto {
    requires java.logging;
    // HMACSpi 仮
    requires java.xml.crypto;
    requires net.siisise;
    requires net.siisise.asn;
    requires net.siisise.xml;
    requires net.siisise.abnf;
    requires net.siisise.abnf.rfc;
    requires net.siisise.rebind;
    exports net.siisise.ietf.pkcs.asn1;
    exports net.siisise.ietf.pkcs1;
    exports net.siisise.ietf.pkcs5;
    exports net.siisise.ietf.pkcs8;
    exports net.siisise.itu_t.x501;
    exports net.siisise.security.block;
    exports net.siisise.security.digest;
    exports net.siisise.security.key;
    exports net.siisise.security.key.mcf;
    exports net.siisise.security.mac;
    exports net.siisise.security.mode;
    exports net.siisise.security.padding;
    exports net.siisise.security.rng;
    exports net.siisise.security.sign;
    exports net.siisise.security.stream;
//    requires softlib.crypto.module;
}
