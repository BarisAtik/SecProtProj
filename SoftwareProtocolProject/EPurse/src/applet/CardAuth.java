package applet;

import javacard.framework.*;
import javacard.framework.APDU;
import javacard.framework.Util;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.applet.Applet;
import java.nio.ByteBuffer;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;
import java.nio.ByteBuffer;
// import ISO7816 class
import javacard.framework.ISO7816;

public class CardAuth {
    private final EPurse purse;

    public CardAuth(EPurse purse) {
        this.purse = purse;
    }

    public void authenticate1(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        //######## START ARROW ONE ########
        // Read the data into the buffer
        apdu.setIncomingAndReceive();

        // unpack data of 8 bytes to terminalID and cardId, both 4 bytes
        byte[] data = new byte[dataLength];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, data, (short) 0, dataLength);
        
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
        //######## END ARROW ONE ########

        boolean auth = true;

        // Check certificate
        // check certificate en als die niet klopt set auth to false
        if (!auth) { // TODO encryption shit with checking certificates. 
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        
        //######## START ARROW TWO ########
        // Send int challenge=42 to the POSTerminal
        short challenge = 42;

        // Use the intToBytes function to convert the challenge to a byte array
        byte[] challengeBytes = intToBytes(challenge);

        // Prepare the APDU
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) challengeBytes.length);

        // Send the challenge
        apdu.sendBytesLong(challengeBytes, (short) 0, (short) challengeBytes.length);

        //######## END ARROW TWO ########
    }

    public void authenticate2(APDU apdu){
        byte[] buffer = apdu.getBuffer();

        //######## START ARROW THREE ########
        // Read the data into the buffer
        apdu.setIncomingAndReceive();
        
        //unpack incremented challenge
        // unpack data of 
        byte[] data = new byte[4];
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, data, (short) 0, (short) 4);

        byte[] challengeResponse = new byte[4];
        
        Util.arrayCopy(data, (short) 0, challengeResponse, (short) 0, (short) 4);

        // Convert to ints
        int challengeResponseInt = ByteBuffer.wrap(challengeResponse).getInt();

        // Print the terminal ID
        System.out.println("challengeResponse : " + challengeResponseInt);
        //######## END ARROW THREE ########

        // Check response with public key


        //######## START ARROW FOUR ########
        purse.cardId = intToBytes(1710);

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) purse.cardId.length);

        // Send the challenge
        apdu.sendBytesLong(purse.cardId, (short) 0, (short) purse.cardId.length);

        //######## END ARROW FOUR ########
    }

    public void authenticate3(APDU apdu){
        byte[] buffer = apdu.getBuffer();
        short dataLength = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);

        //######## START ARROW FIVE ########
        // Read the data into the buffer
        apdu.setIncomingAndReceive();

        
        //######## END ARROW FIVE ########
    }

    public static byte[] intToBytes(int i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(i);
        return bb.array();
    }
}
