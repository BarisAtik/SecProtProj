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


import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class Init {
    private final EPurse purse;

    public Init(EPurse purse) {
        this.purse = purse;
    }

    public void setCardIdAndExpireDate(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
    
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.cardId, (short) 0, (short) 4);
        Util.arrayCopy(buffer, (short) (ISO7816.OFFSET_CDATA + 4), purse.expireDateUnix, (short) 0, (short) 4);

        //System.out.println("Card ID: " + ByteBuffer.wrap(purse.cardId).getInt());
        //System.out.println("Expire date (Unix + 5 years): " + ByteBuffer.wrap(purse.expireDateUnix).getInt());
    }

    public void generateKeypairs(APDU apdu){
        // m_privateKey = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE,KeyBuilder.LENGTH_RSA_1024,false); 
        // m_publicKey = KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC,KeyBuilder.LENGTH_RSA_1024,true); 
        // m_keyPair = new KeyPair(KeyPair.ALG_RSA, (short) m_publicKey.getSize());

        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
        apdu.setIncomingAndReceive();

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.transientData, (short) 0, dataLength);

        // set exponent and modulus
        purse.masterPubKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        purse.masterPubKey.setExponent(purse.transientData, (short) 0, (short) 3);
        purse.masterPubKey.setModulus(purse.transientData, (short) 3, (short) 128);

        System.out.println("Master public key has been set.");

        // ################## DEBUG ##################
        // Print exponent and modulus
        // byte[] bufferExponent = new byte[3]; // Adjust the size as needed
        // byte[] bufferModulus = new byte[128]; // Adjust the size as needed
        // short offset = 0;

        // purse.masterPubKey.getExponent(bufferExponent, offset);
        // BigInteger bigIntExponent = new BigInteger(bufferExponent);
        // System.out.println("Exponent: " + bigIntExponent);

        // purse.masterPubKey.getModulus(bufferModulus, offset);
        // String hexModulus = new BigInteger(1, bufferModulus).toString();
        // System.out.println("Modulus: " + hexModulus);

        
        // Step 5 - Init protocol
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
        purse.cardPrivKey = (RSAPrivateKey) keyPair.getPrivate();
        purse.cardPubKey = (RSAPublicKey) keyPair.getPublic();

        // Put exp and modulus in buffer
        purse.cardPubKey.getExponent(buffer, (short) 0);
        purse.cardPubKey.getModulus(buffer, (short) 3);

        // DEBUG - Print card public key
        byte[] bufferExponent = new byte[3]; // Adjust the size as needed
        byte[] bufferModulus = new byte[128]; // Adjust the size as needed
        short offset = 0;

        purse.cardPubKey.getExponent(bufferExponent, (short) 0);
        purse.cardPubKey.getModulus(bufferModulus, (short) 0);
        BigInteger bigIntExponent = new BigInteger(bufferExponent);
        //System.out.println("Exponent cardPublic: " + bigIntExponent);

        
        String hexModulus = new BigInteger(1, bufferModulus).toString(16);
        System.out.println("(EPurse) Modulus cardPublic: " + hexModulus);

        // Send public key to back-end to get it signed
        apdu.setOutgoingAndSend((short) 0, (short) 131);
    }

    public void setCertificate(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, purse.cardCertificate, (short) 0, (short) 128);

        // copy purse.cardId + purse.expireDateUnix + purse.cardCertificate to transientData
        Util.arrayCopy(purse.cardId, (short) 0, purse.transientData, (short) 0, (short) 4);
        Util.arrayCopy(purse.expireDateUnix, (short) 0, purse.transientData, (short) 4, (short) 4);
        purse.cardPubKey.getModulus(purse.transientData, (short) 8);

        //System.out.println("(EPurse) cardID: " + toHexString(purse.cardId));
        //System.out.println("(EPurse) cardExpireDate: " + toHexString(purse.expireDateUnix));
        System.out.println("(EPurse) transientdata: " + toHexString(purse.transientData));
        //System.out.println("(EPurse) certificate: " + toHexString(purse.cardCertificate));

        // Verify the certificate with master public key
        purse.signatureInstance.init(purse.masterPubKey, Signature.MODE_VERIFY);
        boolean verified = purse.signatureInstance.verify(purse.transientData, (short) 0, (short) 136, purse.cardCertificate,(short) 0, (short)128);
        System.out.println("(EPurse) Certificate verified: " + verified);
    }

    public String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
          sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }
}
