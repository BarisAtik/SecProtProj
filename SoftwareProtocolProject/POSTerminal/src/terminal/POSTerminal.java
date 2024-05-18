package terminal;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import java.nio.ByteBuffer;
import java.util.List;
import java.util.Scanner;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CardTerminals;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;


// imports for using JCardSim 
import com.licel.jcardsim.io.JavaxSmartCardInterface; 
import com.licel.jcardsim.smartcardio.JCardSimProvider; 
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.smartcardio.CardSimulator;

import applet.EPurse;

public class POSTerminal{
    private byte[] terminalCounter;

    //private JavaxSmartCardInterface simulatorInterface; // SIM

    static final byte[] EPURSE_APPLET_AID = { (byte) 0x3B, (byte) 0x29,
            (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };
    static final String EPURSE_APPLET_AID_string = "3B2963616C6301";

    static final CommandAPDU SELECT_APDU = new CommandAPDU(
    		(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, EPURSE_APPLET_AID);
    
    CardChannel applet;

    public POSTerminal() {
        terminalCounter = new byte[]{0x00, 0x00, 0x00, 0x25}; 
        // Create simulator and install applet
        JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();
        selectApplet(simulator);
        
        // Authentication of the EPurse
        authenticateCard(simulator, 69, 3742, terminalCounter);
        
        // Get input from commandline and send it to the applet
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter a command: ");
        int command = scanner.nextInt();
        sendCommandToApplet(simulator, command);
    }

    public static void main(String[] arg) {
        POSTerminal terminal = new POSTerminal();
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
          sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    private void selectApplet(JavaxSmartCardInterface simulator){
        AID EPURSE_AppletAID = new AID(EPURSE_APPLET_AID,(byte)0,(byte)7);
        simulator.installApplet(EPURSE_AppletAID, EPurse.class);

        CommandAPDU SELECT_APDU = new CommandAPDU( (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,EPURSE_APPLET_AID);
        ResponseAPDU response = simulator.transmitCommand(SELECT_APDU);
    }

    private void sendCommandToApplet(JavaxSmartCardInterface simulator, int command){
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) command, (byte) 0x00, (byte) 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        System.out.println("Response: " + toHexString(response.getBytes()));
    }

    public static byte[] intToBytes(int i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(i);
        return bb.array();
    }

    public void authenticateCard(JavaxSmartCardInterface simulator, int terminalID, int cert, byte[] terminalCounter){
        // convert int terminalID to byte[]
        byte[] terminalIDBytes = intToBytes(terminalID);
        byte[] certBytes = intToBytes(cert);
        // concatenate terminalID and cert
        byte[] data = new byte[8];
        System.arraycopy(terminalIDBytes, 0, data, 0, 4);
        System.arraycopy(certBytes, 0, data, 4, 4);

        //######## START ARROW ONE ########

        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, data);
        //CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, terminalIDBytes);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        
        //######## END ARROW ONE ########
        
        //######## START ARROW TWO ########

        // Get the challenge from the response
        byte[] challenge = response.getData();
        // Cast back to int
        int challengeInt = ByteBuffer.wrap(challenge).getInt();
        System.out.println("Challenge: " + challengeInt);

        //######## END ARROW TWO ########

        // Send the challenge back to the applet incremented by 1
        challengeInt++;
        challenge = intToBytes(challengeInt);
        
        // Send instruction 2 to the applet with incremented challenge
        CommandAPDU commandAPDU2 = new CommandAPDU((byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, challenge);
        ResponseAPDU response2 = simulator.transmitCommand(commandAPDU2);

        // Get the response from the applet
        byte[] response2Data = response2.getData();
        int response2Int = ByteBuffer.wrap(response2Data).getInt();
        System.out.println("CardID: " + response2Int);

    }
}
