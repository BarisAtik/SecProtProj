package terminal;

import java.time.*;
import java.time.temporal.ChronoUnit;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.util.Random;

import javax.smartcardio.*;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import com.licel.jcardsim.io.JavaxSmartCardInterface; 
import com.licel.jcardsim.smartcardio.JCardSimProvider; 
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.smartcardio.CardSimulator;

import applet.EPurse;

public class InitTerminal {

    byte[] cardPubExp;
    byte[] cardModulus;
    byte[] cardID;
    byte[] cardExpireDate;

    protected RSAPrivateKey masterPrivateKey;
    protected RSAPublicKey masterPublicKey;

    // Helper Objects
    private final Utils utils;

    InitTerminal() {
        cardModulus = new byte[Constants.KEY_SIZE];
        cardPubExp = new byte[Constants.EXPONENT_SIZE];
        cardID = new byte[Constants.ID_size];
        cardExpireDate = new byte[Constants.EXPIREDATE_size];
        
        utils = new Utils();
    }

    public static void main(String[] arg) {
        InitTerminal terminal = new InitTerminal();
        terminal.setMasterKeyPair();
        // Initialize simulator
        JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();
        terminal.utils.selectApplet(simulator);
        terminal.sendCardIDAndExpireDate(simulator);
        terminal.sendMasterPublicKey(simulator, terminal.masterPublicKey);
        terminal.createCertificate(simulator, terminal.masterPrivateKey);
    }

    public void setMasterKeyPair(){
        // Generate a new key pair
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            masterPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            masterPublicKey = (RSAPublicKey) keyPair.getPublic();
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();
        }
    }

    public void sendCardIDAndExpireDate(JavaxSmartCardInterface simulator){        
        byte[] data = new byte[(Constants.ID_size + Constants.EXPIREDATE_size)];

        // Generate a random signed 2-byte number
        Random rand = new Random();
        int cardIDint = rand.nextInt(Short.MAX_VALUE);
        cardID = utils.intToBytes(cardIDint);
  
        // Get the current Unix timestamp
        Instant now = Instant.now();
        int currentUnixTimestamp = (int) now.getEpochSecond();

        // Add 5 years to the current timestamp
        int expireDate = currentUnixTimestamp + 157680000; // 157680000 seconds = 5 years
        cardExpireDate = utils.intToBytes(expireDate);

        // TEST: Give card a past expire date
        //cardExpireDate = utils.intToBytes(157680000);        

        // Set the card ID and expire date
        System.arraycopy(cardID, 0, data, 0, Constants.ID_size);
        System.arraycopy(cardExpireDate, 0, data, Constants.ID_size, Constants.EXPIREDATE_size);
        
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, data);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
    }

    public int getBalance(JavaxSmartCardInterface simulator){
        return utils.getBalance(simulator);
    }

    public void sendMasterPublicKey(JavaxSmartCardInterface simulator, RSAPublicKey masterPublicKey){
        
        //System.out.println("Master Public Key on Init Terminal: " +  masterPublicKey.toString());

        byte[] pubexp = masterPublicKey.getPublicExponent().toByteArray();
        byte[] modulus = masterPublicKey.getModulus().toByteArray();

        // Print the hex representation of the public exponent and modulus
        // System.out.println("Public Exponent: " + utils.toHexString(pubexp));
        // System.out.println("Modulus: " + utils.toHexString(modulus));
        // System.out.println("Modulus: " + masterPublicKey.getModulus().toString(16));
        
        // Cut the first byte of the modulus which is always 0x00
        byte[] modulusWithoutFirstByte = new byte[modulus.length - 1];
        System.arraycopy(modulus, 1, modulusWithoutFirstByte, 0, modulus.length - 1);

        //System.out.println("Modulus without first byte: " + utils.toHexString(modulusWithoutFirstByte));
        modulus = modulusWithoutFirstByte;
        //System.out.println("Modulus length: " + modulus.length);

        byte[] data = new byte[pubexp.length + modulus.length];
        
        System.arraycopy(pubexp, 0, data, 0, pubexp.length);
        System.arraycopy(modulus, 0, data, pubexp.length, modulus.length);
        
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, data);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // Check the response data
        byte[] responseData = response.getData();
        // Check the length of the response data
        if (responseData.length != (Constants.EXPONENT_SIZE + Constants.KEY_SIZE)) {
            System.out.println("Error: Response data length is not 131 bytes");
            return;
        }
        // Read the card public exponent (3 bytes) and modulus (128 bytes)
        System.arraycopy(responseData, 0, cardPubExp, 0, Constants.EXPONENT_SIZE);
        System.arraycopy(responseData, Constants.EXPONENT_SIZE, cardModulus, 0, Constants.KEY_SIZE);
    }

    public void createCertificate(JavaxSmartCardInterface simulator, RSAPrivateKey masterPrivateKey){

        // create certificate
        // cardID (4 bytes)|| expireDate (4 bytes) || cardExp (3 bytes) || cardModulus (128 bytes)
        byte[] data = new byte[Constants.CERTIFICATE_SIZE];
        System.arraycopy(cardID, 0, data, 0, Constants.ID_size);
        System.arraycopy(cardExpireDate, 0, data, Constants.ID_size, Constants.EXPIREDATE_size);
        System.arraycopy(cardPubExp, 0, data, (Constants.ID_size + Constants.EXPIREDATE_size), Constants.EXPONENT_SIZE);
        System.arraycopy(cardModulus, 0, data, (Constants.ID_size + Constants.EXPIREDATE_size + Constants.EXPONENT_SIZE), Constants.KEY_SIZE);

        //System.out.println("(InitTerminal) cardID: " + utils.toHexString(cardID));
        //System.out.println("(InitTerminal) cardExpireDate: " + utils.toHexString(cardExpireDate));
        //System.out.println("(InitTerminal) cardModulus: " + utils.toHexString(cardModulus));
        //System.out.println("(InitTerminal) Data which has been send: " + utils.toHexString(data));
    
        byte[] certificate = new byte[Constants.SIGNATURE_SIZE];

        // Sign the data with master private key
        try {
            certificate = utils.sign(data, masterPrivateKey);
            // DEBUG: Print size of the certificate
            // System.out.println("(InitTerminal) Certificate which has been send: " + utils.toHexString(certificate));
            // System.out.println("(InitTerminal) Certificate length: " + certificate.length);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }

        //DEBUG: Verify the certificate with master public key
        // try {
        //     boolean verified = utils.verify(data, certificate, masterPublicKey);
        //     System.out.println("(InitTerminal) Certificate verified: " + verified);
        // } catch (Exception e) {
        //     // Handle the exception here
        //     e.printStackTrace();   
        // }

        // Send the certificate to the card
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x03, (byte) 0x00, (byte) 0x00, certificate);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        
        
    }
    
    public byte[] createTerminalCertificate(int terminalID, RSAPublicKey terminalPubKey, RSAPrivateKey masterPrivateKey){
        byte[] terminalIDBytes = utils.intToBytes(terminalID);
        byte[] terminalExponent = terminalPubKey.getPublicExponent().toByteArray();
        byte[] terminalModulus = terminalPubKey.getModulus().toByteArray();

        // Cut the first byte of the modulus which is always 0x00
        byte[] modulusWithoutFirstByte = new byte[terminalModulus.length - 1];
        System.arraycopy(terminalModulus, 1, modulusWithoutFirstByte, 0, terminalModulus.length - 1);
        terminalModulus = modulusWithoutFirstByte;

        byte[] data = new byte[(Constants.ID_size + Constants.EXPONENT_SIZE + Constants.KEY_SIZE)];
        System.arraycopy(terminalIDBytes, 0, data, 0, Constants.ID_size);
        System.arraycopy(terminalExponent, 0, data, Constants.ID_size, Constants.EXPONENT_SIZE);
        System.arraycopy(terminalModulus, 0, data, (Constants.ID_size + Constants.EXPONENT_SIZE), Constants.KEY_SIZE);

        byte[] certificate = new byte[(Constants.ID_size + Constants.EXPONENT_SIZE + Constants.SIGNATURE_SIZE)];
        try {
            certificate = utils.sign(data, masterPrivateKey);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }

        return certificate;
    }
    
}
