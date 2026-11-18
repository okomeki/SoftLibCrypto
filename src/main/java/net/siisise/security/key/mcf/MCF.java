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

    Map<String, ModularCryptFormat> sub;
    String gen;

    public MCF() {
        this("2b");
    }

    /**
     * 生成.
     * @param gen 生成用フォーマット選択
     */
    public MCF(String gen) {
        this.gen = gen;
        sub = new HashMap<>();
        sub.put("", new DEScrypt());
        sub.put("2", new BCryptMCF("2", 10));
        sub.put("2a", new BCryptMCF("2a", 10));
        sub.put("2b", new BCryptMCF());
        sub.put("2x", new BCryptMCF());
        sub.put("2y", new BCryptMCF());
        sub.put("5", new DigestCrypt("5", "SHA-256"));
        sub.put("6", new DigestCrypt("6", "SHA-512"));
    }

    @Override
    public String generate(String pass) {
        ModularCryptFormat mcf;
        mcf = sub.get(gen);
        return mcf.generate(pass);
    }

    @Override
    public boolean verify(String pass, String code) {
        String[] spp = code.split("\\x24");
        ModularCryptFormat mcf;
        if (spp.length > 2) {
            mcf = sub.get(spp[1]);
        } else {
            mcf = sub.get("");
        }
        if (mcf != null) {
            return mcf.verify(pass, code);
        }
        return false;
    }
}
