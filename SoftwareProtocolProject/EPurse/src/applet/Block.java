package applet;

import javacard.framework.*;
import javacard.framework.APDU;
import javacard.framework.Util;

import javax.print.attribute.standard.MediaSize.ISO;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.applet.Applet;
import java.nio.ByteBuffer;

import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacard.framework.ISO7816;

public class Block {
    private final EPurse purse;

    public Block(EPurse purse) {
        this.purse = purse;
    }

    // TODO: check signature of terminal before blocking
    public void block(APDU apdu){
        // Set EPurse to blocked
        System.out.println("(EPurse) Blocking EPurse");
        purse.blocked = true;
    }

    public void sendBlockedStatus(APDU apdu){
        // Send blocked status
        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        // Read the data into the buffer
        apdu.setIncomingAndReceive();

        // Send blocked boolean
        buffer[0] = purse.blocked ? (byte) 0x01 : (byte) 0x00;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }
}
