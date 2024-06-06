package applet;

import javacard.framework.*;
import javacard.framework.APDU;
import javacard.framework.Util;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.applet.Applet;

import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import javacard.framework.ISO7816;

public class CardAuth {
    private final EPurse purse;

    public CardAuth(EPurse purse) {
        this.purse = purse;
    }
    
    // Depends: STATE = initialized
    // After: STATE = DATA_EXCHANGED
    public void exchangeData(APDU apdu){
        // Check if state is initialized
        // if (!purse.initialized) {
        //     ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // }

        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        //######## START ARROW ONE ########
        // Read the data into the buffer
        apdu.setIncomingAndReceive();

        // Receive terminalID || terminalNonce || terminalExponent || terminalModulus
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, dataLength);
        Util.arrayCopy(purse.transientData, (short) 0, purse.terminalId, (short) 0, (short) Constants.ID_size);
        Util.arrayCopy(purse.transientData, (short) Constants.ID_size, purse.terminalNonce, (short) 0, (short) Constants.NONCE_SIZE);
        Util.arrayCopy(purse.transientData, (short) (Constants.ID_size + Constants.NONCE_SIZE), purse.terminalExponent, (short) 0, (short) Constants.EXPONENT_SIZE);
        Util.arrayCopy(purse.transientData, (short) (Constants.ID_size + Constants.NONCE_SIZE + Constants.EXPONENT_SIZE), purse.terminalModulus, (short) 0, (short) Constants.KEY_SIZE);

        purse.terminalPubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        purse.terminalPubKey.setExponent(purse.terminalExponent, (short) 0, (short) 3);
        purse.terminalPubKey.setModulus(purse.terminalModulus, (short) 0, (short) 128);
        
        // Generate random nonce
        purse.randomDataInstance.generateData(purse.cardNonce, (short) 0, (short) Constants.NONCE_SIZE);
        // DEBUG print cardNonce
        //System.out.println("Card nonce: " + purse.cardNonce.toString());

        // Send cardID || cardNonce || cardExpireDate || cardExp || cardMod
        // Put data in transientData
        Util.arrayCopy(purse.cardId, (short) 0, purse.transientData, (short) 0, (short) Constants.ID_size);
        Util.arrayCopy(purse.cardNonce, (short) 0, purse.transientData, (short) Constants.ID_size, (short) Constants.NONCE_SIZE);
        Util.arrayCopy(purse.expireDateUnix, (short) 0, purse.transientData, (short) (Constants.ID_size + Constants.NONCE_SIZE), (short) Constants.EXPIREDATE_size);

        // Put cardExp and cardMod in transientData
        purse.cardPubKey.getExponent(purse.transientData, (short) (Constants.ID_size + Constants.NONCE_SIZE + Constants.EXPIREDATE_size));
        purse.cardPubKey.getModulus(purse.transientData, (short) (Constants.ID_size + Constants.NONCE_SIZE + Constants.EXPIREDATE_size + Constants.EXPONENT_SIZE));

        // Send data
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) purse.transientData.length);
        apdu.sendBytesLong(purse.transientData, (short) 0, (short) purse.transientData.length);

        // Set state to DATA_EXCHANGED
        purse.state[0] = 0x01;

    }

    // Depends: STATE = DATA_EXCHANGED
    public void exchangeCertificate(APDU apdu){
        // Check if state is DATA_EXCHANGED
        // if (purse.state[0] != 0x01) {
        //     System.out.println("State is not DATA_EXCHANGED");
        //     ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // }

        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        apdu.setIncomingAndReceive();

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, dataLength);
        Util.arrayCopy(purse.transientData, (short) 0, purse.terminalSignature, (short) 0, (short) Constants.SIGNATURE_SIZE);

        // put terminalID || terminalExponent || terminalModulus back in transientData
        Util.arrayCopy(purse.terminalId, (short) 0, purse.transientData, (short) 0, (short) Constants.ID_size);
        Util.arrayCopy(purse.terminalExponent, (short) 0, purse.transientData, (short) (Constants.ID_size), (short) Constants.EXPONENT_SIZE);
        Util.arrayCopy(purse.terminalModulus, (short) 0, purse.transientData, (short) (Constants.ID_size + Constants.EXPONENT_SIZE), (short) Constants.KEY_SIZE);
        
        // Verify the signature
        purse.signatureInstance.init(purse.masterPubKey, Signature.MODE_VERIFY);
        boolean verified = purse.signatureInstance.verify(purse.transientData, (short) 0, (short) 135, purse.terminalSignature, (short) 0, (short) 128);
        //System.out.println("(EPurse) Signature verified: " + verified);

        if (!verified) {
            System.out.println("Signature does not match!");
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Send cardCertificate back 
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) purse.cardCertificate.length);
        apdu.sendBytesLong(purse.cardCertificate, (short) 0, (short) purse.cardCertificate.length);
    
        // Set the state to CERTIFICATE_EXCHANGED
        purse.state[0] = 0x02;
    }

    // Depends: STATE = STATE_CERTIFICATE_EXCHANGED
    // After: STATE = STATE_AUTHENTICATED
    public void verifyResponse(APDU apdu){
        // Check if state is CERTIFICATE_EXCHANGED
        // if (purse.state[0] != 0x02) {
        //     System.out.println("State is not CERTIFICATE_EXCHANGED");
        //     ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // }

        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        apdu.setIncomingAndReceive();
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, dataLength);
                
        // Verify the signature
        purse.signatureInstance.init(purse.terminalPubKey, Signature.MODE_VERIFY);
        boolean verified = purse.signatureInstance.verify(purse.cardNonce, (short) 0, (short) 4, purse.transientData, (short) 0, (short) 128);
        System.out.println("(EPurse) Card Nonce Signature verified: " + verified);
        
        if (!verified) {
            System.out.println("Nonce Signature does not match!");
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Send sign(terminalNonce , cardPrivKey) back
        purse.signatureInstance.init(purse.cardPrivKey, Signature.MODE_SIGN);
        short signatureLength = purse.signatureInstance.sign(purse.terminalNonce, (short) 0, (short) 4, purse.transientData, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(signatureLength);
        apdu.sendBytesLong(purse.transientData, (short) 0, signatureLength);

        // Set the state to AUTHENTICATED
        purse.state[0] = 0x03;
    }
}
