package terminal;

import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import java.nio.ByteBuffer;
import java.nio.charset.Charset;
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

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAPublicKeySpec;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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
    private int terminalID;

    protected RSAPrivateKey terminalPrivKey;
    protected RSAPublicKey terminalPubKey;
    protected RSAPublicKey masterPubKey;

    private final Utils utils;
    
    CardChannel applet;

    public POSTerminal(int terminalID) {
        terminalCounter = new byte[]{0x00, 0x00, 0x00, 0x25}; 
        utils = new Utils();
        secureRandom = new SecureRandom(); 
        this.terminalID = terminalID;
    }

    // public static void main(String[] arg) {
    //     POSTerminal terminal = new POSTerminal(123);
    //     terminal.setTerminalKeyPair();
        
    //     // Create simulator and install applet
    //     JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();
    //     terminal.utils.selectApplet(simulator);

    //     // Authentication of the EPurse
    //     terminal.authenticateCard(simulator);
        
    //     // Get input from commandline and send it to the applet
    //     Scanner scanner = new Scanner(System.in);
    //     System.out.println("Enter a command: ");
    //     int command = scanner.nextInt();
    //     terminal.utils.sendCommandToApplet(simulator, command);
    // }

    public void setTerminalKeyPair(){
         try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            terminalPrivKey = (RSAPrivateKey) keyPair.getPrivate();
            terminalPubKey = (RSAPublicKey) keyPair.getPublic();
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();
        }
    }

    public byte[] getPublicModulus(){
        byte[] modulus = terminalPubKey.getModulus().toByteArray();

        byte[] modulusWithoutFirstByte = new byte[modulus.length - 1];
        System.arraycopy(modulus, 1, modulusWithoutFirstByte, 0, modulus.length - 1);

        return modulusWithoutFirstByte;
    }

    public void authenticateCard(JavaxSmartCardInterface simulator){
        // Generate a random number as challenge
        byte[] terminalNonce = new byte[4];
        secureRandom.nextBytes(terminalNonce);
        
        // Send terminalID || terminalNonce || terminalExponent || terminalModulus
        byte[] data = new byte[139];
        byte[] terminalIDBytes = utils.intToBytes(terminalID);
        
        byte[] terminalExponent = terminalPubKey.getPublicExponent().toByteArray();
        byte[] terminalModulus = getPublicModulus();

        System.arraycopy(terminalIDBytes, 0, data, 0, 4);
        System.arraycopy(terminalNonce, 0, data, 4, 4);
        System.arraycopy(terminalExponent, 0, data, 8, 3);
        System.arraycopy(terminalModulus, 0, data, 11, 128);

        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x00, data);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // Receive cardID || cardNonce || cardExpireDate || cardExp || cardMod
        byte[] responseData = response.getData();
        


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
    
    

}
