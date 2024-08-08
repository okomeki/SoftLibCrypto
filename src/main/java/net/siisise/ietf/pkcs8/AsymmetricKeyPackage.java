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
package net.siisise.ietf.pkcs8;

import java.util.Arrays;
import java.util.List;
import net.siisise.bind.Rebind;
import net.siisise.bind.format.TypeFormat;

/**
 * ASN.1 X.690 DER 出力が必要.
 * ASN.1 X.690 BER 受信に対応する必要あり.
 */
public class AsymmetricKeyPackage {
    OneAsymmetricKey[] keys;
    
    public <V> V rebind(TypeFormat<V> format) {
        List list = Arrays.asList(keys);
        return Rebind.valueOf(list, format);
    }
}
