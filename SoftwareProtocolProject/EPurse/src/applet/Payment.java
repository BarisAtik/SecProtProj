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

public class Payment {
    private final EPurse purse;

    public Payment(EPurse purse) {
        this.purse = purse;
    }

    public void substractMoney(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        //######## START ARROW TWO ########
        // Read the data into the buffer
        apdu.setIncomingAndReceive();

        // Receive amount (4 bytes)|| terminalCounter (4 bytes)|| Signature (128 bytes)
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, dataLength);

        // Check amount (4 bytes) ||  terminalCounter (4 bytes) with the signature 
        // Verify signature
        purse.signatureInstance.init(purse.terminalPubKey, Signature.MODE_VERIFY);
        boolean verified = purse.signatureInstance.verify(purse.transientData, (short) 0, (short) 6, purse.transientData, (short) 6, (short) 128);
        System.out.println("transaction Signature verified: " + verified);

        if(!verified){
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Copy amount to purse.amount
        Util.arrayCopy(purse.transientData, (short) 0, purse.amount, (short) 0, (short) 2);

        if (!sufficientFunds()) {
            System.out.println("Insufficient funds: ABORTING TRANSACTION");
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        } 

        // Update balance
        updateBalance();
        
        // DEBUG Print remaining balance
        System.out.println("Remaining balance: " + Util.getShort(purse.balance, (short) 0));

        
    }

    public boolean sufficientFunds() {
        return Util.getShort(purse.balance, (short) 0) >= Util.getShort(purse.amount, (short) 0);
    }   

    public void updateBalance() {
        Util.setShort(purse.balance, (short) 0, (short) (Util.getShort(purse.balance, (short) 0) - Util.getShort(purse.amount, (short) 0)));
    }

    // DEBUG REMOVE THIS
    public int bytesToInt(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return bb.getInt();
    }
}
