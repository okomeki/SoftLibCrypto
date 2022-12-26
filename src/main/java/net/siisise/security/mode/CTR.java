package net.siisise.security.mode;

import net.siisise.io.Packet;
import net.siisise.io.PacketA;
import net.siisise.security.block.Block;

/**
 * Counter 
 * ivは適当な実装
 */
public class CTR extends StreamMode {

    Packet xp;

    public CTR(Block b) {
        super(b);
    }
    
    /**
     * 
     * @param b 暗号またはハッシュ関数
     * @param key
     * @param iv counter の初期値 - 1を含む長さで
     */
    public CTR(Block b, byte[] key, byte[] iv) {
        super(b);
        init(key, iv);
    }

    /**
     * 
     * @param key (block パラメータ),CTR iv
     */
    @Override
    public void init(byte[]... key) {
        byte[][] nkey = new byte[key.length - 1][];
        System.arraycopy(key, 0, nkey, 0, key.length - 1);
        super.init(nkey);

        int vlen = block.getBlockLength() / 8;
        byte[] vecsrc = key[key.length - 1];
        // iv
        byte[] v = new byte[vlen];
        System.arraycopy(vecsrc, 0, v, 0, Math.min(vecsrc.length, v.length));
        vectori = btoi(v);

        xp = new PacketA();
        next();
    }

    void next() {
        // カウントするだけ
        int x = vectori.length;
        do {
            x--;
            vectori[x]++;
        } while (vectori[x] == 0 && x != 0);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset) {
        byte[] ret = itob(block.encrypt(vectori, 0));
        for (int i = 0; i < ret.length; i++) {
            ret[i] ^= src[offset + i];
        }
        next();
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return encrypt(src, offset);
    }

    @Override
    public byte[] encrypt(byte[] src, int offset, int length) {
        int rl = length - xp.size();
        for ( int i = 0; i < rl; i+= 16 ) { // 並列化すると速いかも
            xp.write(itob(block.encrypt(vectori,0)));
            next();
        }
        byte[] ret = new byte[src.length];
        xp.read(ret);
        for (int i = 0; i < ret.length; i++ ) {
            ret[i] ^= src[offset+i];
        }
        return ret;
    }

    @Override
    public byte[] decrypt(byte[] src, int offset, int length) {
        return encrypt(src, offset, length);
    }

    @Override
    public int[] encrypt(int[] src, int offset) {
        int[] ret = block.encrypt(vectori, 0);
        for (int i = 0; i < ret.length; i++ ) {
            ret[i] ^= src[offset + i];
        }
        next();
        return ret;
    }

    @Override
    public int[] decrypt(int[] src, int offset) {
        return encrypt(src, offset);
    }
}
