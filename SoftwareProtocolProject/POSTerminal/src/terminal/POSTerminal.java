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
    public int terminalID;
    private byte[] terminalCert;

    // Variables for card
    public byte[] cardID;
    public byte[] cardNonce;
    public byte[] cardExpireDate;
    public byte[] cardExp;
    public byte[] cardMod;
    public byte[] cardCertificate;
    public byte[] cardSignedNonce;
    
    protected RSAPrivateKey terminalPrivKey;
    protected RSAPublicKey terminalPubKey;
    protected RSAPublicKey masterPubKey;

    private final Utils utils;
    
    CardChannel applet;

    public POSTerminal(int terminalID, RSAPublicKey masterPubKey) {
        terminalCounter = new byte[]{0x00, 0x00, 0x00, 0x25}; 
        terminalCert = new byte[128];
         
        this.terminalID = terminalID;
        this.masterPubKey = masterPubKey;

        cardID = new byte[4];
        cardNonce = new byte[4];
        cardExpireDate = new byte[4];
        cardExp = new byte[3];
        cardMod = new byte[128];
        cardCertificate = new byte[128];

        utils = new Utils();
        secureRandom = new SecureRandom();
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
    
    public void setTerminalCertificate(byte[] terminalCert){
        this.terminalCert = terminalCert;
    }

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

        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, data);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // Receive cardID (4 bytes)|| cardNonce (4 bytes) || cardExpireDate (4 bytes) || cardExp (3 bytes)|| cardMod (128 bytes)
        byte[] responseData = response.getData();
        System.arraycopy(responseData, 0, cardID, 0, 4);
        System.arraycopy(responseData, 4, cardNonce, 0, 4);
        System.arraycopy(responseData, 8, cardExpireDate, 0, 4);
        System.arraycopy(responseData, 12, cardExp, 0, 3);
        System.arraycopy(responseData, 15, cardMod, 0, 128);

        // Terminal sends Certificate to card
        CommandAPDU commandAPDU2 = new CommandAPDU((byte) 0x00, (byte) 0x05, (byte) 0x00, (byte) 0x00, terminalCert);
        ResponseAPDU response2 = simulator.transmitCommand(commandAPDU2);

        byte[] response2Data = response2.getData();
        System.arraycopy(response2Data, 0, cardCertificate, 0, 128);

        // Verify contents with the certificate
        byte[] dataToVerify = new byte[139];
        System.arraycopy(cardID, 0, dataToVerify, 0, 4);
        System.arraycopy(cardExpireDate, 0, dataToVerify, 4, 4);
        System.arraycopy(cardExp, 0, dataToVerify, 8, 3);
        System.arraycopy(cardMod, 0, dataToVerify, 11, 128);

        try {
            boolean verified = utils.verify(dataToVerify, cardCertificate, masterPubKey);
            System.out.println("(POSTerminal) Certificate verified: " + verified);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }
        
        // Increment, sign and send signed nonce to card
        byte[] incrementedNonce = utils.incrementByteArray(cardNonce);
        byte[] signedNonce = utils.sign(incrementedNonce, terminalPrivKey);
        
        CommandAPDU commandAPDU3 = new CommandAPDU((byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x00, signedNonce);
        ResponseAPDU response3 = simulator.transmitCommand(commandAPDU3);

        // // Receive signed nonce from card
        // byte[] response3Data = response3.getData();
        // System.arraycopy(response3Data, 0, cardSignedNonce, 0, 4);
        // // Check if the signed card nonce is correct
        //byte [] incrementedTerminalNonce = utils.incrementByteArray(terminalNonce);
        // try {
        //     boolean verified = utils.verify(cardSignedNonce, incrementedTerminalNonce, masterPubKey);
        //     System.out.println("(POSTerminal) Card nonce verified: " + verified);
        // } catch (Exception e) {
        //     // Handle the exception here
        //     e.printStackTrace();   
        // }
    }
    
    

}
