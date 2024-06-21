package applet;

import javacard.framework.*;

import javax.print.attribute.standard.MediaSize.ISO;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;

import javacard.security.Signature;
import javacard.security.RandomData;

public class EPurse extends javacard.framework.Applet implements ISO7816 {
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
        cardId = new byte[Constants.ID_size];
        balance = new byte[Constants.BALANCE_SIZE];
        cardCounter = new byte[]{0x00, 0x00, 0x00, 0x00}; 
        expireDateUnix = new byte[]{0x00, 0x00, 0x00, 0x00};
        cardCertificate = new byte[Constants.SIGNATURE_SIZE];
        blocked = false;
        initialized = false;

        // Card variables
        state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        transientData = JCSystem.makeTransientByteArray((short) 255, JCSystem.CLEAR_ON_RESET);
        cardNonce = JCSystem.makeTransientByteArray((short) Constants.NONCE_SIZE, JCSystem.CLEAR_ON_DESELECT); 
        
        // Terminal variables
        terminalId = JCSystem.makeTransientByteArray((short) Constants.ID_size, JCSystem.CLEAR_ON_DESELECT);
        terminalSignature = JCSystem.makeTransientByteArray((short) Constants.SIGNATURE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        terminalModulus = JCSystem.makeTransientByteArray((short) Constants.SIGNATURE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        terminalExponent = JCSystem.makeTransientByteArray((short) Constants.EXPONENT_SIZE, JCSystem.CLEAR_ON_DESELECT);
        terminalNonce = JCSystem.makeTransientByteArray((short) Constants.NONCE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        terminalCounter = JCSystem.makeTransientByteArray((short) Constants.COUNTER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        amount = JCSystem.makeTransientByteArray((short) Constants.BALANCE_SIZE, JCSystem.CLEAR_ON_DESELECT);
        
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

        // Ignore the APDU that selects this applet
        if (selectingApplet()) {
            return;
        }
        
        if (initialized == false && ins > 3) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Check if the card is blocked
        if (blocked) {
            ins = 17;
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        switch (ins) {
            case 1:
                init.setCardIdAndExpireDate(apdu);
                break;
            case 2:
                init.generateKeypairs(apdu);
                break;
            case 3:
                init.setCertificate(apdu);
                break;
            case 4:
                cardAuth.exchangeData(apdu);
                break;
            case 5:
                cardAuth.exchangeCertificate(apdu);
                break;
            case 6: 
                cardAuth.verifyResponse(apdu);
                break;
            case 7:
                payment.substractMoney(apdu);
                break;
            case 8:
                payment.addMoney(apdu);
                break;
            case 9:
                payment.sendBalance(apdu);
                break;
            case 16:
                block.block(apdu);
                break;
            case 17:
                block.sendBlockedStatus(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }

    }

}