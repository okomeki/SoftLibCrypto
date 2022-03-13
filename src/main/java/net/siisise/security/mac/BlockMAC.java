package net.siisise.security.mac;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;
import net.siisise.security.io.BlockIOListener;
import net.siisise.security.io.BlockIOOutputStream;

/**
 * Block系をもっていないときになんとかする
 */
public abstract class BlockMAC implements MAC,BlockIOListener {
    
    BlockIOOutputStream pac;

    @Override
    public void init(byte[] key) {
        pac = new BlockIOOutputStream(this);
    }

    @Override
    public void update(byte[] src) {
        update(src,0,src.length);
    }

    @Override
    public void update(byte[] src, int offset, int length) {
        try {
            pac.write(src, offset, length);
        } catch (IOException ex) {
            Logger.getLogger(BlockMAC.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    @Override
    public byte[] doFinal(byte[] src) {
        update(src);
        return doFinal();
    }

    @Override
    public byte[] doFinal() {
        try {
            pac.close();
        } catch (IOException ex) {
            Logger.getLogger(BlockMAC.class.getName()).log(Level.SEVERE, null, ex);
        }
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public int getMacLength() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    // listener
    
    @Override
    public int getBitBlockLength() {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }

    @Override
    public void flush() throws IOException {
    }

    @Override
    public void close() throws IOException {
        throw new UnsupportedOperationException("Not supported yet."); // Generated from nbfs://nbhost/SystemFileSystem/Templates/Classes/Code/GeneratedMethodBody
    }
    
}
