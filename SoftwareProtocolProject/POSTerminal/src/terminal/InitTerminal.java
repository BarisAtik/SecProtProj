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
        cardModulus = new byte[128];
        cardPubExp = new byte[3];
        cardID = new byte[4];
        cardExpireDate = new byte[4];
        

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
        byte[] data = new byte[8];

        // Generate a random unsigned 2-byte number
        int cardIDint = 65533; // 65536 is 2^16
        cardID = utils.intToBytes(cardIDint);
  
        // Get the current Unix timestamp
        Instant now = Instant.now();
        int currentUnixTimestamp = (int) now.getEpochSecond();

        // Add 5 years to the current timestamp
        int expireDate = currentUnixTimestamp + 157680000; // 157680000 seconds = 5 years
        cardExpireDate = utils.intToBytes(expireDate);

        // Set the card ID and expire date
        System.arraycopy(cardID, 0, data, 0, 4);
        System.arraycopy(cardExpireDate, 0, data, 4, 4);
        
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x05, (byte) 0x00, (byte) 0x00, data);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
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
        
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x00, data);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // Check the response data
        byte[] responseData = response.getData();
        // Check the length of the response data
        if (responseData.length != 131) {
            System.out.println("Error: Response data length is not 131 bytes");
            return;
        }
        // Read the card public exponent (3 bytes) and modulus (128 bytes)
        System.arraycopy(responseData, 0, cardPubExp, 0, 3);
        System.arraycopy(responseData, 3, cardModulus, 0, 128);
    }

    public void createCertificate(JavaxSmartCardInterface simulator, RSAPrivateKey masterPrivateKey){

        // create certificate
        // cardID (4 bytes)|| expireDate (4 bytes) || cardModulus (128 bytes)
        byte[] data = new byte[136];
        System.arraycopy(cardID, 0, data, 0, 4);
        System.arraycopy(cardExpireDate, 0, data, 4, 4);
        System.arraycopy(cardModulus, 0, data, 8, 128);

        //System.out.println("(InitTerminal) cardID: " + utils.toHexString(cardID));
        //System.out.println("(InitTerminal) cardExpireDate: " + utils.toHexString(cardExpireDate));
        //System.out.println("(InitTerminal) cardModulus: " + utils.toHexString(cardModulus));
        //System.out.println("(InitTerminal) Data which has been send: " + utils.toHexString(data));
    
        byte[] certificate = new byte[136];

        // Sign the data with master private key
        try {
            certificate = utils.sign(data, masterPrivateKey);
            System.out.println("(InitTerminal) Certificate which has been send: " + utils.toHexString(certificate));
            //System.out.println("(InitTerminal) Certificate length: " + certificate.length);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }

        // Verify the certificate with master public key
        try {
            boolean verified = utils.verify(data, certificate, masterPublicKey);
            System.out.println("(InitTerminal) Certificate verified: " + verified);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }

        // Send the certificate to the card
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x07, (byte) 0x00, (byte) 0x00, certificate);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        
        
    }
    

    
}
