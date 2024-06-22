package applet;

import javacard.framework.*;
import javacard.framework.APDU;
import javacard.framework.Util;

import javax.print.attribute.standard.MediaSize.ISO;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacard.framework.ISO7816;

public class Payment {
    private final EPurse purse;

    public Payment(EPurse purse) {
        this.purse = purse;
    }

    // Reload protocol for ReloadTerminal
    public void addMoney(APDU apdu){
        // Check if state is authenticated
        if(purse.state[0] != 0x03){
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        // Read the data into the buffer
        apdu.setIncomingAndReceive();

        // Receive amount (2 bytes)|| terminalCounter (2 bytes)|| Signature (128 bytes)
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, dataLength);

        // Check amount (2 bytes) ||  terminalCounter (2 bytes) with the signature 
        // Verify signature
        purse.signatureInstance.init(purse.terminalPubKey, Signature.MODE_VERIFY);
        boolean verified = purse.signatureInstance.verify(purse.transientData, (short) 0, (short) (Constants.BALANCE_SIZE + Constants.COUNTER_SIZE), purse.transientData, (short) 4, (short) Constants.SIGNATURE_SIZE);

        if(!verified){
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Copy amount to purse.amount
        Util.arrayCopy(purse.transientData, (short) 0, purse.amount, (short) 0, (short) Constants.BALANCE_SIZE);
        Util.arrayCopy(purse.transientData, (short) Constants.BALANCE_SIZE, purse.terminalCounter, (short) 0, (short) Constants.COUNTER_SIZE);

        // Update balance
        if (!reloadPossible()) {
            // Overwrite first byte of transientData with M = 0 indicating reload not possible
            purse.transientData[0] = 0;
        } else {
            increaseBalance();
            purse.transientData[0] = 1;
        }

        // Increment terminalCounter (2 bytes)
        purse.terminalCounter = incrementCounter(purse.terminalCounter);
        // Put terminalCounter after M in transientData
        Util.arrayCopy(purse.terminalCounter, (short) 0, purse.transientData, (short) 1, (short) Constants.COUNTER_SIZE);

        // Create signature for M (1 byte) || terminalCounter++ (2 bytes) with card private key
        purse.signatureInstance.init(purse.cardPrivKey, Signature.MODE_SIGN);
        short signatureLength = purse.signatureInstance.sign(purse.transientData, (short) 0, (short) 3, purse.transientData, (short) 3);

        // Send M || Signature
        Util.arrayCopy(purse.transientData, (short) 0, buffer, (short) 0, (short) 1);
        Util.arrayCopy(purse.transientData, (short) 3, buffer, (short) 1, signatureLength);
        
        // Send response
        apdu.setOutgoingAndSend((short) 0, (short) (1 + signatureLength));

    }

    // Payment protocol for POSTerminal
    public void substractMoney(APDU apdu){
        // Check if state is authenticated
        if(purse.state[0] != 0x03){
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        // Read the data into the buffer
        apdu.setIncomingAndReceive();

        // Receive amount (2 bytes)|| terminalCounter (2 bytes)|| Signature (128 bytes)
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, dataLength);

        // Check amount (2 bytes) ||  terminalCounter (2 bytes) with the signature 
        // Verify signature
        purse.signatureInstance.init(purse.terminalPubKey, Signature.MODE_VERIFY);
        boolean verified = purse.signatureInstance.verify(purse.transientData, (short) 0, (short) (Constants.BALANCE_SIZE + Constants.COUNTER_SIZE), purse.transientData, (short) 4, (short) Constants.SIGNATURE_SIZE);

        if(!verified){
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // Copy amount to purse.amount
        Util.arrayCopy(purse.transientData, (short) 0, purse.amount, (short) 0, (short) Constants.BALANCE_SIZE);
        Util.arrayCopy(purse.transientData, (short) Constants.BALANCE_SIZE, purse.terminalCounter, (short) 0, (short) Constants.COUNTER_SIZE);   

        if (!sufficientFunds()) {
            // Overwrite first byte of transientData with M = 0 indicating insufficient funds
            purse.transientData[0] = 0;
        } else {
            // Update balance
            decreaseBalance();
            // Overwrite first byte of transientData with M = 1 indicating sufficient funds
            purse.transientData[0] = 1;
        }

        // Increment terminalCounter (2 bytes)
        purse.terminalCounter = incrementCounter(purse.terminalCounter);
        // Put terminalCounter after M in transientData
        Util.arrayCopy(purse.terminalCounter, (short) 0, purse.transientData, (short) 1, (short) Constants.COUNTER_SIZE);

        // Create signature for M (1 byte) || terminalCounter++ (2 bytes) with card private key
        purse.signatureInstance.init(purse.cardPrivKey, Signature.MODE_SIGN);
        short signatureLength = purse.signatureInstance.sign(purse.transientData, (short) 0, (short) 3, purse.transientData, (short) 3);

        // Send M || Signature
        Util.arrayCopy(purse.transientData, (short) 0, buffer, (short) 0, (short) 1);
        Util.arrayCopy(purse.transientData, (short) 3, buffer, (short) 1, signatureLength);
        
        // Send response
        apdu.setOutgoingAndSend((short) 0, (short) (1 + signatureLength));
    }

    public void sendBalance(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopy(purse.balance, (short) 0, buffer, (short) 0, (short) 2);
        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }

    public void increaseBalance() {
        Util.setShort(purse.balance, (short) 0, (short) (Util.getShort(purse.balance, (short) 0) + Util.getShort(purse.amount, (short) 0)));
    }

    public void decreaseBalance() {
        Util.setShort(purse.balance, (short) 0, (short) (Util.getShort(purse.balance, (short) 0) - Util.getShort(purse.amount, (short) 0)));
    }

    public byte[] incrementCounter(byte[] counter){
        short counterValue = Util.getShort(counter, (short) 0);
        counterValue++;
        Util.setShort(counter, (short) 0, counterValue);
        return counter;
    }

    // Boolean function to check if sufficient funds are available
    public boolean sufficientFunds() {
        return Util.getShort(purse.balance, (short) 0) >= Util.getShort(purse.amount, (short) 0) && Util.getShort(purse.amount, (short) 0) >= 0 ;
    }

    // Boolean function to check if reload is possible i.e amount + balance <= 300 EUR and amount >= 0
    public boolean reloadPossible() {
        return Util.getShort(purse.balance, (short) 0) + Util.getShort(purse.amount, (short) 0) <= 30000 && Util.getShort(purse.amount, (short) 0) >= 0;
    }
}
