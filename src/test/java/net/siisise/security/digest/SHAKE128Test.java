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
    public void testByteMsg() throws IOException {
        System.out.println("SHAKE128 ByteMsg");
        List<String> names = List.of(
                "SHAKE128ShortMsg.rsp",
                "SHAKE128LongMsg.rsp");

        for ( String fname : names ) {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(SHAKE128Test.class.getResourceAsStream("/nist/shakebytetestvectors/" + fname), "utf-8"));
            String line;
            do {
                line = in.readLine();
            } while (line.length() > 0);

            Map<String,String> struct = readMap(in);
            int outlen = Integer.parseInt(struct.get("Outputlen"));

            struct = readMap(in);
            while (struct != null) {
                int Len = Integer.parseInt(struct.get("Len"));
                byte[] Msg = Bin.toByteArray(struct.get("Msg"));
                byte[] Output = Bin.toByteArray(struct.get("Output"));

                SHAKE128 shake = new SHAKE128(outlen);
                shake.update(Msg, 0, Len/8);
                byte[] result = shake.digest();
                assertArrayEquals(Output, result, "SHAKE128:" + Len);
                struct = readMap(in);
            }

            in.close();
        }
    }

    Map<String,String> readMap(BufferedReader in) throws IOException {
        Map<String,String> outMap = new HashMap();
        String line = in.readLine();
        while (line != null && line.length() > 0) {
            if (line.charAt(0) == '[') {
                line = line.substring(1, line.length() - 1);
            }
            String[] sp = line.split("=");
            outMap.put(sp[0].strip(), sp[1].strip());
//            System.out.println(sp[0].strip()+" :"+ sp[1].strip());
            line = in.readLine();
        }
        if (outMap.isEmpty()) return null;
        return outMap;
    }

    @Test
    public void testBitMsg() throws IOException {
        System.out.println("SHAKE128 BitMsg");
        List<String> names = List.of(
                "SHAKE128ShortMsg.rsp",
                "SHAKE128LongMsg.rsp");

        for ( String fname : names ) {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(SHAKE128Test.class.getResourceAsStream("/nist/shakebittestvectors/" + fname), "utf-8"));
            String line;
            do {
                line = in.readLine();
            } while (line.length() > 0);

            Map<String,String> struct = readMap(in);
            int outlen = Integer.parseInt(struct.get("Outputlen"));

            struct = readMap(in);
            while (struct != null) {
                int Len = Integer.parseInt(struct.get("Len"));
                byte[] Msg = Bin.toByteArray(struct.get("Msg"));
                byte[] Output = Bin.toByteArray(struct.get("Output"));

                SHAKE128 shake = new SHAKE128(outlen);
                shake.writeBit(Msg, 0, Len);
                byte[] result = shake.digest();
                assertArrayEquals(Output, result, "SHAKE128:" + Len);
                struct = readMap(in);
            }

            in.close();
        }
    }
/*
    @Test
    public void testByteMonte() throws IOException {
        System.out.println("SHAKE128 Byte Monte");
        List<String> names = List.of(
                "SHAKE128Monte.rsp");

        for ( String fname : names ) {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(SHAKE128Test.class.getResourceAsStream("/nist/shakebytetestvectors/" + fname), "utf-8"));
            String line;
            do {
                line = in.readLine();
            } while (line.length() > 0);

            Map<String,String> struct = readMap(in);
            int minOutLen = Integer.parseInt(struct.get("Minimum Output Length (bits)"));
            int minoutbytes = minOutLen / 8;

            struct = readMap(in);
            int maxOutLen = Integer.parseInt(struct.get("Maximum Output Length (bits)"));
            int maxoutbytes = maxOutLen / 8;

            struct = readMap(in);
            byte[] Msg = Bin.toByteArray(struct.get("Msg"));
            int Range =(maxoutbytes - minoutbytes + 1);
            int Len = Msg.length * 8;
            int Outputlen = maxOutLen/8 * 8;

            struct = readMap(in);
            while (struct != null) {
                int COUNT = Integer.parseInt(struct.get("COUNT"));
                Outputlen = Integer.parseInt(struct.get("Outputlen"));
                byte[] Output = Bin.toByteArray(struct.get("Output"));
                int n = 0;
                for (int i = 0; i < 1000; i++) {
                    SHAKE128 shake = new SHAKE128(Outputlen * 8);
                    shake.write(Msg);
                    Msg = shake.digest();
                    int Rightmost_Output_bits = (Msg[Msg.length - 1] & 0xff) | (Msg[Msg.length - 2] & 0xff);
                    if ( i == 999) {
                        n = Outputlen;
                    }
                    Outputlen = minoutbytes + (Rightmost_Output_bits % Range);
                }
                System.out.println(Bin.toHex(Msg));
                System.out.println("Outputlen:" + n);
                assertArrayEquals(Output, Msg, "SHAKE128:Byte:Monte" + COUNT);
                struct = readMap(in);
            }

            in.close();
        }
    }
*/
/*
    @Test
    public void testBitMonteMsg() throws IOException {
        System.out.println("SHAKE128 Bit Monte");
        List<String> names = List.of(
                "SHAKE128Monte.rsp");

        for ( String fname : names ) {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(SHAKE128Test.class.getResourceAsStream("/nist/shakebittestvectors/" + fname), "utf-8"));
            String line;
            do {
                line = in.readLine();
            } while (line.length() > 0);

            Map<String,String> struct = readMap(in);
            int minimum = Integer.parseInt(struct.get("Minimum Output Length (bits)"));

            struct = readMap(in);
            int maximum = Integer.parseInt(struct.get("Maximum Output Length (bits)"));

            struct = readMap(in);
            byte[] Msg = Bin.toByteArray(struct.get("Outputlen"));

            struct = readMap(in);
            while (struct != null) {
                int COUNT = Integer.parseInt(struct.get("COUNT"));
                int Len = Integer.parseInt(struct.get("Outputlen"));
                byte[] Output = Bin.toByteArray(struct.get("Output"));
                for (int i = 0; i < 1000; i++) {
                    SHAKE128 shake = new SHAKE128(Len);
                    shake.writeBit(Msg, 0, Len);
                    Msg = shake.digest();
                }
                assertArrayEquals(Output, Msg, "SHAKE128:" + Len);
                struct = readMap(in);
            }

            in.close();
        }
    }
*/
}
