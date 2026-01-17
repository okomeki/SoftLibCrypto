package net.siisise.security.digest;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import net.siisise.io.BigBitPacket;
import net.siisise.lang.Bin;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

/**
 *
 */
public class SHAKE256Test {

    public SHAKE256Test() {
    }

    @Test
    public void testShortMsg1() {
        System.out.println("shortMsg1:");
        byte[] MSG = new byte[0];
        byte[] exResult = Bin.toByteArray("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
        SHAKE shake = new SHAKE256(256l);
        byte[] result = shake.digest(MSG);
        System.out.println(Bin.toHex(exResult));
        System.out.println(Bin.toHex(result));
        assertArrayEquals(exResult, result);
    }

    @Test
    public void testShortMsg2() {
        System.out.println("shortMsg2:");
        byte[] MSG = new byte[]{0x0f};
        BigBitPacket bbp = new BigBitPacket();
        bbp.writeBit(0x0f, 8);
        byte[] exResult = Bin.toByteArray("aabb07488ff9edd05d6a603b7791b60a16d45093608f1badc0c9cc9a9154f215");
        SHAKE shake = new SHAKE256(256l);
        byte[] result = shake.digest(MSG);
        System.out.println(Bin.toHex(exResult));
        System.out.println(Bin.toHex(result));
        assertArrayEquals(exResult, result);
    }

    @Test
    public void testValiableOut() {
        System.out.println("valiableMsg:");
        byte[] MSG = Bin.toByteArray("c61a9188812ae73994bc0d6d4021e31bf124dc72669749111232da7ac29e61c4");
        byte[] exResult = Bin.toByteArray("23ce");
        SHAKE256 shake = new SHAKE256(16l);
        byte[] result = shake.digest(MSG);
        System.out.println(Bin.toHex(exResult));
        System.out.println(Bin.toHex(result));
        assertArrayEquals(exResult, result);
    }

    Map<String, String> readMap(BufferedReader in) throws IOException {
        Map<String, String> outMap = new HashMap();
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
        if (outMap.isEmpty()) {
            return null;
        }
        return outMap;
    }

    @Test
    public void testByteMsg() throws IOException {
        System.out.println("SHAKE256 ByteMsg");
        List<String> names = List.of(
                "SHAKE256ShortMsg.rsp",
                "SHAKE256LongMsg.rsp");

        for (String fname : names) {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(SHAKE256Test.class.getResourceAsStream("/nist/shakebytetestvectors/" + fname), "utf-8"));
            String line;
            do {
                line = in.readLine();
            } while (line.length() > 0);

            Map<String, String> struct = readMap(in);
            int outlen = Integer.parseInt(struct.get("Outputlen"));

            struct = readMap(in);
            while (struct != null) {
                int Len = Integer.parseInt(struct.get("Len"));
                byte[] Msg = Bin.toByteArray(struct.get("Msg"));
                byte[] Output = Bin.toByteArray(struct.get("Output"));

                SHAKE256 shake = new SHAKE256(outlen);
                shake.update(Msg, 0, Len / 8);
                byte[] result = shake.digest();
                assertArrayEquals(Output, result, "SHAKE256:" + Len);
                struct = readMap(in);
            }

            in.close();
        }
    }

    @Test
    public void testBitMsg() throws IOException {
        System.out.println("SHAKE256 BitMsg");
        List<String> names = List.of(
                "SHAKE256ShortMsg.rsp",
                "SHAKE256LongMsg.rsp");

        for (String fname : names) {
            BufferedReader in = new BufferedReader(
                    new InputStreamReader(SHAKE256Test.class.getResourceAsStream("/nist/shakebittestvectors/" + fname), "utf-8"));
            String line;
            do {
                line = in.readLine();
            } while (line.length() > 0);

            Map<String, String> struct = readMap(in);
            int outlen = Integer.parseInt(struct.get("Outputlen"));

            struct = readMap(in);
            while (struct != null) {
                int Len = Integer.parseInt(struct.get("Len"));
                byte[] Msg = Bin.toByteArray(struct.get("Msg"));
                byte[] Output = Bin.toByteArray(struct.get("Output"));
     
                SHAKE256 shake = new SHAKE256(outlen);
                shake.writeBit(Msg, 0, Len);
                byte[] result = shake.digest();
                assertArrayEquals(Output, result, "SHAKE256:" + Len);
                struct = readMap(in);
            }

            in.close();
        }
    }
}
