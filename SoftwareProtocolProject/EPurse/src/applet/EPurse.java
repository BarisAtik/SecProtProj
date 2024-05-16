package applet;

import javacard.framework.*;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.applet.Applet;
import java.nio.ByteBuffer;

public class EPurse extends javacard.framework.Applet implements ISO7816 {
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
            case 1: // Authenticate the card 
                System.out.println("I am doing INS 1");
                // Get the length of the incoming data
                short dataLength = (short) (buffer[OFFSET_LC] & 0x00FF);

                // Check if the APDU has incoming data
                if (dataLength > 0) {
                    // Read the data into the buffer
                    apdu.setIncomingAndReceive();

                    // unpack data of 8 bytes to terminalID and cardId, both 4 bytes
                    byte[] data = new byte[dataLength];
                    Util.arrayCopy(buffer, OFFSET_CDATA, data, (short) 0, dataLength);
                    byte[] terminalId = new byte[4];
                    byte[] cert = new byte[4];
                    Util.arrayCopy(data, (short) 0, terminalId, (short) 0, (short) 4);
                    Util.arrayCopy(data, (short) 4, cert, (short) 0, (short) 4);

                    // Convert to ints
                    int terminalIdInt = ByteBuffer.wrap(terminalId).getInt();
                    int certInt = ByteBuffer.wrap(cert).getInt();

                    // Print the terminal ID
                    System.out.println("Terminal ID: " + terminalIdInt);
                    System.out.println("Cert: " + certInt);

                    // int terminalId = ByteBuffer.wrap(buffer, OFFSET_CDATA, dataLength).getInt();

                    // // Print the terminal ID
                    // System.out.println("Terminal ID: " + terminalId);
                }
                break;
            case 2: 
                System.out.println("I am doing INS 2");
                buffer[0] = (byte) 0x25; // Store the byte '37' in the response buffer
                break;
            case 3:
                System.out.println("I am doing INS 3");
                byte[] helloWorldBytes = "Hello World is the best line".getBytes();
                System.arraycopy(helloWorldBytes, 0, buffer, 0, helloWorldBytes.length);
                apdu.setOutgoingAndSend((short) 0, (short) helloWorldBytes.length);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }

    }

}