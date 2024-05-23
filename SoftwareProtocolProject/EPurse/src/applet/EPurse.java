package applet;

import javacard.framework.*;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.applet.Applet;
import java.nio.ByteBuffer;
import javacard.security.Signature;
import javacard.security.RandomData;

public class EPurse extends javacard.framework.Applet implements ISO7816 {
    // Constants (TO DO: Move to Constants.java)
    final static short ID_SIZE = 4;
    final static short COUNTER_SIZE = 4;
    final static short SIGNATURE_SIZE = 4;//256;

    // Transient variables
    protected final byte[] state;
    protected final byte[] terminalId;
    protected final byte[] terminalSignature;
    protected final byte[] terminalPubKey;
    protected final byte[] transientData;
    protected final byte[] terminalNonce;
    protected final byte[] nonce;

    // Persistent variables
    protected byte[] balance; 
    protected byte[] cardCounter; 
    protected byte[] cardId;
    protected final byte[] expireDateUnix;
    protected boolean blocked;
    protected boolean initialized;

    // Helper objects
    private final CardAuth cardAuth;
    final Signature signatureInstance;
    final RandomData randomData;


    EPurse() {
        cardId = new byte[4];
        balance = new byte[]{0x00, 0x00, 0x00, 0x00}; 
        cardCounter = new byte[]{0x00, 0x00, 0x00, 0x00}; 
        expireDateUnix = new byte[]{0x00, 0x00, 0x00, 0x00};
        blocked = false;
        initialized = false;

        state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        terminalId = JCSystem.makeTransientByteArray((short) ID_SIZE, JCSystem.CLEAR_ON_DESELECT);
        terminalSignature = JCSystem.makeTransientByteArray((short) SIGNATURE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        terminalPubKey = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
        transientData = JCSystem.makeTransientByteArray((short) (8), JCSystem.CLEAR_ON_RESET);
        terminalNonce = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        nonce = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);

        cardAuth = new CardAuth(this);

        signatureInstance = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register();
    }
    
    public static void install(byte[] array, short offset, byte length) throws SystemException{
        new EPurse();
    }
    
    public void process(APDU apdu) throws ISOException, APDUException { 
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];
        System.out.println("INS: " + ins);

        // Ignore the APDU that selects this applet
        if (selectingApplet()) {
            return;
        }

        switch (ins) {
            case 1: // Authenticate the card 
                System.out.println("Authenticating the card...");
                cardAuth.authenticate1(apdu);
                break;
            case 2: 
                System.out.println("Checking the response...");
                cardAuth.authenticate2(apdu);
                break;
            case 3:
                System.out.println("Authenticating the terminal...");
                cardAuth.authenticate3(apdu);
                break;
            case 4:
                System.out.println("Lekker bezig mannn");
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                // byte[] helloWorldBytes = "Hello World is the best line".getBytes();
                // System.arraycopy(helloWorldBytes, 0, buffer, 0, helloWorldBytes.length);
                // apdu.setOutgoingAndSend((short) 0, (short) helloWorldBytes.length);
                break;
        }

    }

}