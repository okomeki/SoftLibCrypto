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
package net.siisise.security.digest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.siisise.lang.Bin;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class SHAKE128Test {
    
    public SHAKE128Test() {
    }

    @Test
    public void testSomeMethod() {
        System.out.println("SHAKE128 bitout test");
        byte[] ex = Bin.toByteArray("7f9c2ba4");
        
        SHAKE128 shake = new SHAKE128(4093);
        byte[] result = shake.digest();
        System.out.println(Bin.toHex(result));
    }
    
    @Test
    public void testShortMsg() throws IOException {
        System.out.println("SHAKE128 ShortMsg");
        List<String> names = List.of("SHAKE128ShortMsg.rsp","SHAKE128LongMsg.rsp");

        for ( String fname : names ) {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(SHAKE128Test.class.getResourceAsStream("/nist/shakebytetestvectors/" + fname), "utf-8"));
            String line;
            do {
                line = in.readLine();
            } while (line.length() > 0);

            Map<String,String> outMap = new HashMap();
            line = in.readLine();
            while (line.length() > 0) {
                line = line.substring(1, line.length() - 1);
                String[] sp = line.split(" ");
                outMap.put(sp[0], sp[2]);
                line = in.readLine();
            }

            int outlen = Integer.parseInt(outMap.get("Outputlen"));

            Map<String, String> struct = new HashMap<>();

            do {
                line = in.readLine();
                while (line != null && line.length() > 0) {
                    String[] sp = line.split(" ");
                    struct.put(sp[0], sp[2]);
                    line = in.readLine();
                }
                int Len = Integer.parseInt(struct.get("Len"));
                byte[] Msg = Bin.toByteArray(struct.get("Msg"));
                byte[] Output = Bin.toByteArray(struct.get("Output"));
                System.out.println("SHAKE128:" + Len);
                System.out.println(Bin.toHex(Msg));
                System.out.println(Bin.toHex(Output));

                SHAKE128 shake = new SHAKE128(outlen);
                shake.update(Msg, 0, Len/8);
                byte[] result = shake.digest();
                assertArrayEquals(Output, result, "SHAKE128:" + Len);
            } while (line != null);


            in.close();
        }
    }
    
}
