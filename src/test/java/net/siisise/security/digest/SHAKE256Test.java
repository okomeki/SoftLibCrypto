package net.siisise.security.digest;

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
        byte[] MSG = new byte[] { 0x0f };
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
}
