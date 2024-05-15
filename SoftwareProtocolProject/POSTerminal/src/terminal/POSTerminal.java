package terminal;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
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

    //private JavaxSmartCardInterface simulatorInterface; // SIM

    static final byte[] EPURSE_APPLET_AID = { (byte) 0x3B, (byte) 0x29,
            (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };
    static final String EPURSE_APPLET_AID_string = "3B2963616C6301";

    static final CommandAPDU SELECT_APDU = new CommandAPDU(
    		(byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, EPURSE_APPLET_AID);
    
    CardChannel applet;

    public POSTerminal() {
        // Create simulator and install applet
        JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();
        selectApplet(simulator);
        
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
    
    public static byte[] intToBytes(int value) {
        byte[] byteValue = new byte[4];
        byteValue[0] = (byte) (value >> 24);
        byteValue[1] = (byte) (value >> 16);
        byteValue[2] = (byte) (value >> 8);
        byteValue[3] = (byte) value;
        return byteValue;
    }

    private void sendCommandToApplet(JavaxSmartCardInterface simulator, int command){
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) command, (byte) 0x00, (byte) 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        System.out.println("Response: " + toHexString(response.getBytes()));
    }
}
