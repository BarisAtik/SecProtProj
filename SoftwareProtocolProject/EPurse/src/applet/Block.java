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

// DEBUG REMOVE THIS
import java.nio.ByteBuffer;

public class Block {
    private final EPurse purse;

    public Block(EPurse purse) {
        this.purse = purse;
    }

    // TODO: check signature of terminal before blocking
    public void block(APDU apdu){
        // Get the signature data from the APDU
        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        // Read the data into the buffer
        apdu.setIncomingAndReceive();

        // Copy to transient data
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, (short) 128);

        // Verify signature with cardID
        purse.signatureInstance.init(purse.terminalPubKey, Signature.MODE_VERIFY);
        boolean verified = purse.signatureInstance.verify(purse.cardId, (short) 0, (short) 4, purse.transientData, (short) 0, (short) 128);
        
        // Set EPurse to blocked
        if(verified){
            purse.blocked = true;
        }
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

    


    // DEBUG REMOVE THIS
    // public int bytesToInt(byte[] bytes) {
    //     ByteBuffer bb = ByteBuffer.wrap(bytes);
    //     return bb.getInt();
    // }
}
