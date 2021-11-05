package net.siisise.security.block;

/**
 * 3DES. TDEA DESede.
 * とある暗号アルゴリズム.
 * 
 * ANSI X9.52-1998
 * @deprecated AES
 */
public class TripleDES extends OneBlock {

    private DES block1;
    private DES block2;
    private DES block3;
    
    TripleDES() {
        block1 = new DES();
        block2 = new DES();
        block3 = new DES();
    }
    
    @Override
    public void init(byte[] key) {
        byte[] k1 = new byte[8];
        byte[] k2 = new byte[8];
        byte[] k3 = new byte[8];

        switch ( key.length ) {
            case 8:
                System.arraycopy(key, 0, k1, 0, 8);
                init(k1,k1);
                break;
            case 16:
                System.arraycopy(key, 0, k1, 0, 8);
                System.arraycopy(key, 8, k2, 0, 8);
                init(k1,k2);
                break;
            case 24:
                System.arraycopy(key, 0, k1, 0, 8);
                System.arraycopy(key, 8, k2, 0, 8);
                System.arraycopy(key, 16, k3, 0, 8);
                init(k1,k2,k3);
                break;
            default:
                throw new UnsupportedOperationException();
        }
    }

    /**
     * 鍵2個でとりぷるDES。
     * @param k1 鍵1 1回目と3回目に使用する。
     * @param k2 鍵2 2回目に使用する。
     */
    @Override
    public void init(byte[] k1, byte[] k2) {
        block1.init(k1);
        block2.init(k2);
        block3.init(k1);
    }

    public void init(byte[] k1, byte[] k2, byte[] k3) {
        block1 = new DES();
        ((DES)block1).init(k1);
        block2 = new DES();
        ((DES)block2).init(k2);
        block3 = new DES();
        ((DES)block3).init(k3);
    }
    
    @Override
    public int getBlockLength() {
        return block1.getBlockLength();
    }
    
    @Override
    public byte[] encrypt(byte[] src, int offset) {
        return block1.encrypt(block2.decrypt(block3.encrypt(src, offset),0),0);
    }

    @Override
    public byte[] decrypt(byte[] src, int offset) {
        return block3.decrypt(block2.encrypt(block1.decrypt(src, offset),0),0);
    }
}
