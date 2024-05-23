package terminal;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import java.nio.ByteBuffer;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.util.List;
import java.util.Scanner;
import java.util.Base64;
// import filereader object
import java.io.*;

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

import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.math.BigInteger;

import applet.EPurse;

// For randomness like generating a nonce
import java.security.SecureRandom;

public class POSTerminal{
    private SecureRandom secureRandom;
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
        secureRandom = new SecureRandom(); // Initialize SecureRandom
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
        // Initialize the public key


        String masterPublicKey = "MIICWwIBAAKBgGpGtRZEWD/PfUHsl34jCeWe3o9doVqmppgN+/oVQuQApXpPCv2u5tFjNUU1nhxfOfpEn1HOSyr11QI7BVEAenFuwVqIRKKZiLfIZYR7y4wTfAmDyhP8s9qrE+EV299izCW13bb8n+444Lv3yWKBXKPpRlxAVhlVGP0CU6Z2gapDAgMBAAECgYARZL0ihdEDsIvJjFVG+akXAadfQ22zDm9Zl4BT78Lg2hI7MFCWMFfqkRgY2auk7RjqEu0YUHEQ+OcB1HMMTM29KJZWrm5EGLqL6RtSCPAb5Ti+avuVI9xqY6XyaLCvISKaca8aFFO5GJH93mGHvhruxyHfkz2wSIxBNkRqhDLNQQJBALhL3BD8jFrhSTDU6U063nXSPC04TtuGEkli00ifGCBnLeQFG7BYYIQZf9m+ktE9EL4n+a7Io3c4ikeL79yRVHMCQQCTn/KJrzp/y9aQ5oBA5EoCjwgbF51VE6p/kLx+o+/WhVeRdpDPXPPNnzkNrwPSnocK1aslZ2ExKRsTn3RUya7xAkEAqCqId3OLOw4hNA7Dh/Y0sfwRbw3XXxbart4ffz+0yzR7OnqyxloOT9vYvr7Xx1faZDmj6qooBwyvmROG3pQ6IwJAVryBmpgUPQYdGaH09SusuHglgRWM4XHemXkG5zmXL2nFG7iYON4aeVP2B64vBs8R9TG5jw6Asou+Vvc3OKIPYQJABPLa/kn6zLjkloLoO4rAMC3NnWN9mNusix7++t98bxS3MDXqivcFGLOhGin3rKFfrcIjR378oDsL0cWeLUpuLw==";
        // try {
        //     masterPublicKey = new String(Files.readAllBytes(Paths.get("/home/parallels/SecProtProj/SoftwareProtocolProject/POSTerminal/src/terminal/PrivateMasterKey.txt")));
        // } catch (IOException e) {
        //     e.printStackTrace();
        // }
    
        // Convert the public key to a byte array
        byte[] mpk = Base64.getDecoder().decode(masterPublicKey);
        // byte[] mpk = masterPublicKey.getBytes();
        // Print length of the public key
        System.out.println("Length of the public key: " + mpk.length);
        // concatenate terminalID and cert
        byte[] data = new byte[255];
        byte[] nonce = new byte[2]; // Assuming a 2-byte nonce
        secureRandom.nextBytes(nonce);

        System.arraycopy(terminalIDBytes, 0, data, 0, 4);
        System.arraycopy(certBytes, 0, data, 4, 4);
        System.arraycopy(nonce, 0, data, 8, 2);
        System.arraycopy(mpk, 0, data, 10, mpk.length);

        //######## START ARROW ONE ########
        // Send the data to the applet
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, data);
        //CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, data);
        //CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, terminalIDBytes);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        
        // //######## END ARROW ONE ########
        
        // //######## START ARROW TWO ########

        // // Get the challenge from the response
        // byte[] challenge = response.getData();
        // // Cast back to int
        // int challengeInt = ByteBuffer.wrap(challenge).getInt();
        // System.out.println("Challenge: " + challengeInt);

        // //######## END ARROW TWO ########


        // // Check the challenge (for now just increment and send back)
        // challengeInt++;
        // challenge = intToBytes(challengeInt);
        
        
        // //######## START ARROW THREE ########

        // // Send instruction 2 to the applet with counter (IT IS NOW CHALLENGE INCREMENTED, MUST BE CHANGED)
        // CommandAPDU commandAPDU2 = new CommandAPDU((byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, challenge);
        // ResponseAPDU response2 = simulator.transmitCommand(commandAPDU2);

        // //######## END ARROW THREE ########


        // //######## START ARROW FOUR ########

        // // Get the response from the applet
        // byte[] response2Data = response2.getData();
        // int response2Int = ByteBuffer.wrap(response2Data).getInt();
        // System.out.println("CardIDx x: " + response2Int);

        // //######## END ARROW FOUR ########



        // //######## START ARROW FIVE ########
        // CommandAPDU commandAPDU3 = new CommandAPDU((byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x00, challenge);
        // ResponseAPDU response3 = simulator.transmitCommand(commandAPDU3);
        // //######## END ARROW FIVE ########



        // //######## START ARROW SIX ########
        //  byte[] response3Data = response2.getData();
        // int response3Int = ByteBuffer.wrap(response3Data).getInt();
        // System.out.println("CardIDx x: " + response3Int);
        // //######## END ARROW SIX ########

    }
    
    // public static byte[] loadPublicKeyFromFile(String filename) throws Exception {
    //     String publicKeyPEM = new String(Files.readAllBytes(Paths.get(filename)));
        
    //     publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "")
    //                                .replace("-----END PUBLIC KEY-----", "")
    //                                .replaceAll("\\s", "");

    //     return Base64.getDecoder().decode(publicKeyPEM);
    // }

}
