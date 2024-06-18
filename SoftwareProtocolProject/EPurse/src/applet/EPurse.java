package applet;

import javacard.framework.*;

import javax.print.attribute.standard.MediaSize.ISO;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.applet.Applet;
import java.nio.ByteBuffer;
import java.time.chrono.IsoEra;

import javacard.security.Signature;
import javacard.security.RandomData;

public class EPurse extends javacard.framework.Applet implements ISO7816 {
    // Constants (TO DO: Move to Constants.java)
    final static short ID_SIZE = 4;
    final static short COUNTER_SIZE = 4;
    final static short SIGNATURE_SIZE = 128;//256;

    // Transient variables
    protected byte[] state;
    protected byte[] terminalId;
    protected byte[] terminalSignature;
    protected byte[] terminalModulus;
    protected byte[] terminalExponent;
    protected byte[] terminalCounter;
    protected byte[] transientData;
    protected byte[] terminalNonce;
    protected byte[] cardNonce;
    protected byte[] amount;

    // Persistent variables
    protected byte[] balance; 
    protected byte[] cardCounter; 
    protected byte[] cardId;
    protected byte[] cardCertificate;
    protected final byte[] expireDateUnix;
    protected javacard.security.RSAPrivateKey cardPrivKey;
    protected javacard.security.RSAPublicKey cardPubKey;
    protected javacard.security.RSAPublicKey masterPubKey;
    protected javacard.security.RSAPublicKey terminalPubKey;
    protected boolean blocked;
    protected byte[] blocked_status;
    protected boolean initialized;
    

    // Helper objects
    private final CardAuth cardAuth;
    private final Payment payment;
    private final Init init;
    private final Block block;
    final Signature signatureInstance;
    final RandomData randomDataInstance;

    EPurse() {
        cardId = new byte[4];
        //balance = new byte[]{0x01, (byte) 0xF4};
        balance = new byte[2];
        cardCounter = new byte[]{0x00, 0x00, 0x00, 0x00}; 
        expireDateUnix = new byte[]{0x00, 0x00, 0x00, 0x00};
        cardCertificate = new byte[128];
        blocked = false;
        initialized = false;

        // Card variables
        state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        transientData = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);
        cardNonce = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT); 
        
        // Terminal variables
        terminalId = JCSystem.makeTransientByteArray((short) ID_SIZE, JCSystem.CLEAR_ON_DESELECT);
        terminalSignature = JCSystem.makeTransientByteArray((short) SIGNATURE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        terminalModulus = JCSystem.makeTransientByteArray((short) 128, JCSystem.CLEAR_ON_DESELECT);
        terminalExponent = JCSystem.makeTransientByteArray((short) 3, JCSystem.CLEAR_ON_DESELECT);
        terminalNonce = JCSystem.makeTransientByteArray((short) 4, JCSystem.CLEAR_ON_DESELECT);
        terminalCounter = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        amount = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        
        cardAuth = new CardAuth(this);
        payment = new Payment(this);
        init = new Init(this);
        block = new Block(this);

        signatureInstance = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
        randomDataInstance = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        register();
    }
    
    public static void install(byte[] array, short offset, byte length) throws SystemException{
        new EPurse();
    }
    
    public void process(APDU apdu) throws ISOException, APDUException { 
        byte[] buffer = apdu.getBuffer();
        byte ins = buffer[OFFSET_INS];
        System.out.println("(EPurse) INS: " + ins);

        // Ignore the APDU that selects this applet
        if (selectingApplet()) {
            return;
        }

        // Check if the card is blocked
        if (blocked) {
            System.out.println("(EPurse) Card is blocked");
            ins = 17;
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        switch (ins) {
            case 1:
                System.out.println("(EPurse) Setting card ID and expire date...");
                init.setCardIdAndExpireDate(apdu);
                break;
            case 2:
                System.out.println("(EPurse) Generating keypairs...");
                init.generateKeypairs(apdu);
                break;
            case 3:
                System.out.println("(EPurse) Setting certificate...");
                init.setCertificate(apdu);
                break;
            case 4:
                System.out.println("(EPurse) Exchanging data...");
                cardAuth.exchangeData(apdu);
                break;
            case 5:
                System.out.println("(EPurse) Verifying certificate...");
                cardAuth.exchangeCertificate(apdu);
                break;
            case 6: 
                System.out.println("(EPurse) Verifying response...");
                cardAuth.verifyResponse(apdu);
                break;
            case 7:
                System.out.println("(EPurse) Substracting money...");
                payment.substractMoney(apdu);
                break;
            case 8:
                System.out.println("(EPurse) Adding money...");
                payment.addMoney(apdu);
                break;
            case 9:
                System.out.println("(EPurse) Checking balance...");
                payment.sendBalance(apdu);
                break;
            case 16:
                System.out.println("(EPurse) End Of Life...");
                block.block(apdu);
                break;
            case 17:
                //System.out.println("(EPurse) Sending blocked status...");
                block.sendBlockedStatus(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }

    }

}