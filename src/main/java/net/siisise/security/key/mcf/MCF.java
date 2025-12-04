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
package net.siisise.security.key.mcf;

import java.util.HashMap;
import java.util.Map;

/**
 * 階層化っぽいMCF
 */
public class MCF implements ModularCryptFormat {
    
    ModularCryptFormat gen;
    Map<String,ModularCryptFormat> sub;
    
    public MCF(ModularCryptFormat gen) {
        this.gen = gen;
        sub = new HashMap<>();
    }

    @Override
    public String generate(String pass) {
        return gen.generate(pass);
    }

    @Override
    public boolean verify(String pass, String code) {
        String[] spp = code.split("\\x24");
        if (spp.length > 2) {
            ModularCryptFormat mcf = sub.get(spp[1]);
            if (mcf != null) {
                return mcf.verify(pass, code);
            }
            
        }
        return false;
    }
}
