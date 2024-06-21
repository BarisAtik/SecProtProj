package applet;

import javacard.framework.APDU;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

import javax.print.attribute.standard.MediaSize.ISO;

public class Init {
    private final EPurse purse;

    public Init(EPurse purse) {
        this.purse = purse;
    }

    public void setCardIdAndExpireDate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
    
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.cardId, (short) 0, (short) Constants.ID_size);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + Constants.ID_size), purse.expireDateUnix, (short) 0, (short) Constants.EXPIREDATE_size);
    }

    public void generateKeypairs(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, (short) 131);

        // set exponent and modulus
        purse.masterPubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        purse.masterPubKey.setExponent(purse.transientData, (short) 0, (short) Constants.EXPONENT_SIZE);
        purse.masterPubKey.setModulus(purse.transientData, (short) Constants.EXPONENT_SIZE, (short) Constants.KEY_SIZE);

        // Step 5 - Init protocol
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
        purse.cardPrivKey = (RSAPrivateKey) keyPair.getPrivate();
        purse.cardPubKey = (RSAPublicKey) keyPair.getPublic();

        // Put exp and modulus in buffer
        purse.cardPubKey.getExponent(buffer, (short) 0);
        purse.cardPubKey.getModulus(buffer, (short) Constants.EXPONENT_SIZE);

        // Send public key to back-end to get it signed
        apdu.setOutgoingAndSend((short) 0, (short) (Constants.EXPONENT_SIZE + Constants.KEY_SIZE));
    }

    public void setCertificate(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.cardCertificate, (short) 0, (short) Constants.SIGNATURE_SIZE);

        // copy purse.cardId + purse.expireDateUnix + purse.cardCertificate to transientData
        Util.arrayCopy(purse.cardId, (short) 0, purse.transientData, (short) 0, (short) Constants.ID_size);
        Util.arrayCopy(purse.expireDateUnix, (short) 0, purse.transientData, (short) Constants.ID_size, (short) Constants.EXPIREDATE_size);
        
        purse.cardPubKey.getExponent(purse.transientData, (short) (Constants.ID_size + Constants.EXPIREDATE_size));
        purse.cardPubKey.getModulus(purse.transientData, (short) (Constants.ID_size + Constants.EXPIREDATE_size + Constants.EXPONENT_SIZE));

        // Verify the certificate with master public key
        purse.signatureInstance.init(purse.masterPubKey, Signature.MODE_VERIFY);
        boolean verified = purse.signatureInstance.verify(purse.transientData, (short) 0, (short) 139, purse.cardCertificate, (short) 0, (short) Constants.SIGNATURE_SIZE);

        // Set state to initialized
        if (verified) {
            purse.initialized = true;
        } else {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        
    }

    public String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
          sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
