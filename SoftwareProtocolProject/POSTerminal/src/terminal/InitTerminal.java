package terminal;

import java.time.*;
import java.time.temporal.ChronoUnit;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;

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
        // Initialize simulator
        JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();
        terminal.utils.selectApplet(simulator);
        terminal.sendCardIDAndExpireDate(simulator);
        terminal.sendMasterPublicKey(simulator);
        terminal.createCertificate(simulator);
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

    public void sendMasterPublicKey(JavaxSmartCardInterface simulator){
        //
        RSAPublicKey masterPublicKey = utils.readX509PublicKey();
        //System.out.println("Master Public Key on Init Terminal: " +  masterPublicKey.toString());

        byte[] pubexp = masterPublicKey.getPublicExponent().toByteArray();
        byte[] modulus = masterPublicKey.getModulus().toByteArray();

        byte[] data = new byte[pubexp.length + modulus.length];
        
        System.arraycopy(pubexp, 0, data, 0, pubexp.length);
        System.arraycopy(modulus, 0, data, pubexp.length, modulus.length);
        
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x00, data);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // Check the response data
        byte[] responseData = response.getData();
        // Read the card public exponent (3 bytes) and modulus (128 bytes)
        System.arraycopy(responseData, 0, cardPubExp, 0, 3);
        System.arraycopy(responseData, 3, cardModulus, 0, 128);
    }

    public void createCertificate(JavaxSmartCardInterface simulator){
        // Read private key from file
        RSAPrivateKey masterPrivateKey = utils.readPKCS8PrivateKey();

        // create certificate
        // cardID (4 bytes)|| expireDate (4 bytes) || cardModulus (128 bytes)
        byte[] data = new byte[136];
        System.arraycopy(cardID, 0, data, 0, 4);
        System.arraycopy(cardExpireDate, 0, data, 4, 4);
        System.arraycopy(cardModulus, 0, data, 8, 128);

        // Sign the data with master private key
        try {
            byte[] certificate = utils.sign(data, masterPrivateKey);
            System.out.println("Certificate: " + utils.toHexString(certificate));
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();
            byte[] certificate = new byte[0];
        }

        // Send the certificate to the card

        
        
    }
    

    
}
