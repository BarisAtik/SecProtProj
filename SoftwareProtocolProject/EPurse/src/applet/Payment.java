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

        // Receive amount (2 bytes)|| terminalCounter (2 bytes)|| Signature (128 bytes)
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, dataLength);

        // Check amount (4 bytes) ||  terminalCounter (4 bytes) with the signature 
        // Verify signature
        purse.signatureInstance.init(purse.terminalPubKey, Signature.MODE_VERIFY);
        boolean verified = purse.signatureInstance.verify(purse.transientData, (short) 0, (short) 4, purse.transientData, (short) 4, (short) 128);
        System.out.println("(EPURSE) transaction Signature verified: " + verified);

        if(!verified){
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Copy amount to purse.amount
        Util.arrayCopy(purse.transientData, (short) 0, purse.amount, (short) 0, (short) 2);
        Util.arrayCopy(purse.transientData, (short) 2, purse.terminalCounter, (short) 0, (short) 2);   

        if (!sufficientFunds()) {
            System.out.println("Insufficient funds: ABORTING TRANSACTION");
            // Overwrite first byte of transientData with M = 0 indicating insufficient funds
            purse.transientData[0] = 0;
        } else {
            // Update balance
            updateBalance();
            // Overwrite first byte of transientData with M = 1 indicating sufficient funds
            purse.transientData[0] = 1;
        }

        // Increment terminalCounter (2 bytes)
        purse.terminalCounter = incrementCounter(purse.terminalCounter);
        // Put terminalCounter after M in transientData
        Util.arrayCopy(purse.terminalCounter, (short) 0, purse.transientData, (short) 1, (short) 2);

        // DEBUG Print remaining balance
        //System.out.println("Remaining balance: " + Util.getShort(purse.balance, (short) 0));
        //System.out.println("Counter value: " + Util.getShort(purse.terminalCounter, (short) 0));

        // Create signature for M (1 byte) || terminalCounter++ (2 bytes) with card private key
        purse.signatureInstance.init(purse.cardPrivKey, Signature.MODE_SIGN);
        short signatureLength = purse.signatureInstance.sign(purse.transientData, (short) 0, (short) 3, purse.transientData, (short) 3);

        // Send M || Signature
        Util.arrayCopy(purse.transientData, (short) 0, buffer, (short) 0, (short) 1);
        Util.arrayCopy(purse.transientData, (short) 3, buffer, (short) 1, signatureLength);
        
        // Send response
        apdu.setOutgoingAndSend((short) 0, (short) (1 + signatureLength));
    }


    // Increment byte[] counter using Util.getShort and Util.setShort
    public byte[] incrementCounter(byte[] counter){
        short counterValue = Util.getShort(counter, (short) 0);
        counterValue++;
        Util.setShort(counter, (short) 0, counterValue);
        return counter;
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
