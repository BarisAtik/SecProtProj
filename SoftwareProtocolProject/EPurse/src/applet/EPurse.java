package applet;

import javacard.framework.*;

public class EPurse extends Applet implements ISO7816 {
    // Transient variables
    protected final byte[] state;

    // Persistent variables
    protected byte[] balance; 
    protected byte[] cardCounter; 
    protected final byte[] cardId;
    protected final byte[] expireDateUnix;
    protected boolean blocked;
    protected boolean initialized;

    // Helper objects

    EPurse() {
        cardId = new byte[4];
        balance = new byte[]{0x00, 0x00, 0x00, 0x00}; 
        cardCounter = new byte[]{0x00, 0x00, 0x00, 0x00}; 
        expireDateUnix = new byte[]{0x00, 0x00, 0x00, 0x00};
        blocked = false;
        initialized = false;

        state = JCSystem.makeTransientByteArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        
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
            case 1:
                System.out.println("I am doing INS 1");
                buffer[0] = (byte) 0x09; // Store the byte '1' in the response buffer
                break;
            case 2:
                System.out.println("I am doing INS 2");
                buffer[0] = (byte) 0x25; // Store the byte '37' in the response buffer
                break;
            case 3:
                System.out.println("I am doing INS 3");
                byte[] helloWorldBytes = "Hello World".getBytes();
                System.arraycopy(helloWorldBytes, 0, buffer, 0, helloWorldBytes.length);
                apdu.setOutgoingAndSend((short) 0, (short) helloWorldBytes.length);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }

    }

}