package applet;

import javacard.framework.*;

public class EPurse extends Applet implements ISO7816 {
    // Constants and variables for card initialization
    // Constants and variables for card state (e.g., balance, expiry date)
    // Constants and variables for cryptographic keys

    EPurse() {
        // Initialize card state
        // Initialize cryptographic keys
        register();
    }
    
    public static void install(byte[] array, short offset, byte length) throws SystemException{
        // Perform applet installation
        // Initialize card state
        // Initialize cryptographic keys
        // Register applet
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

        //buffer[0] = (byte) 0x25; // Store the byte '37' in the response buffer
        //apdu.setOutgoingAndSend((short) 0, (short) 1); // Set outgoing length to 1 and send response

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
                // Convert 'Hello World' to bytes
                byte[] helloWorldBytes = "Hello World".getBytes();
                // Copy 'Hello World' bytes to the response buffer
                System.arraycopy(helloWorldBytes, 0, buffer, 0, helloWorldBytes.length);
                // Set outgoing length to the length of 'Hello World' and send response
                apdu.setOutgoingAndSend((short) 0, (short) helloWorldBytes.length);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                break;
        }
        //apdu.setOutgoingAndSend((short) 0, (short) 1); // Set outgoing length to 1 and send response

    }


    // Make the functions (your protocols) here such as: Authenticate, SignForReload, SignForPOS, Reload, POSOnline, POSOffline

}