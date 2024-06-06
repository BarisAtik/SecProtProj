package terminal;

import java.time.*;
import java.time.temporal.ChronoUnit;

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
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import java.math.BigInteger;

import applet.EPurse;

public class reloadTerminal{
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
    protected RSAPublicKey cardPubKey;
    protected RSAPublicKey masterPubKey;

    private final Utils utils;
    
    CardChannel applet;

    public reloadTerminal(int terminalID, RSAPublicKey masterPubKey) {
        terminalCounter = new byte[]{0x00, 0x00}; 
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
        //-----------------------------SEND TERMINAL DATA---------------------------------------------------
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

        //-----------------------------RECEIVE CARD DATA---------------------------------------------------

        // Receive cardID (4 bytes)|| cardNonce (4 bytes) || cardExpireDate (4 bytes) || cardExp (3 bytes)|| cardMod (128 bytes)
        byte[] responseData = response.getData();
        System.arraycopy(responseData, 0, cardID, 0, 4);
        System.arraycopy(responseData, 4, cardNonce, 0, 4);
        System.arraycopy(responseData, 8, cardExpireDate, 0, 4);
        System.arraycopy(responseData, 12, cardExp, 0, 3);
        System.arraycopy(responseData, 15, cardMod, 0, 128);

        // Make the public key of the card from the cardMod and the cardExp using setExponent and setModulus
       try {
            cardPubKey = utils.getPublicKey(cardExp, cardMod);
       } catch (Exception e) {
            e.printStackTrace();
       }

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
            System.out.println("(reloadTerminal) Certificate verified: " + verified);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }

        //-----------------------------SIGN CARD NONCE---------------------------------------------------
        
        // sign and send signed nonce to card
        byte[] cardNonceSignature = new byte[128];
        try {
            cardNonceSignature = utils.sign(cardNonce, terminalPrivKey);
            // System.out.println("(reloadTerminal) cardNonceSignature size: " + cardNonceSignature.length); 
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();
        }

        // verifyResponse(cardNonceSignature);
        CommandAPDU commandAPDU3 = new CommandAPDU((byte) 0x00, (byte) 0x06, (byte) 0x00, (byte) 0x00, cardNonceSignature);
        ResponseAPDU response3 = simulator.transmitCommand(commandAPDU3);

        // Receive sign(terminalNonce)
        byte[] response3Data = response3.getData();
        cardSignedNonce = response3Data;
    
        // Verify the signature        
        try {
            boolean verified = utils.verify(terminalNonce, cardSignedNonce, cardPubKey);
            System.out.println("(reloadTerminal) Terminal Nonce Signature verified: " + verified);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }

        //------------------------------CHECK EXPIRY DATE--------------------------------------------------
        // Check if the card is expired 
        byte[] currentDate = utils.getCurrentDate();
        byte[] expireDate = new byte[4];
        System.arraycopy(cardExpireDate, 0, expireDate, 0, 4);

        if(utils.isPastDate(expireDate, currentDate)){
            System.out.println("(reloadTerminal) Card is expired!");
        } else {
            System.out.println("(reloadTerminal) Card is not expired!");
        }

        // If card is expired, send command to block the card
        if(utils.isPastDate(expireDate, currentDate)){
            CommandAPDU commandAPDU4 = new CommandAPDU((byte) 0x00, (byte) 16, (byte) 0x00, (byte) 0x00);
            ResponseAPDU response4 = simulator.transmitCommand(commandAPDU4);
        }
    }

    public void performReload(JavaxSmartCardInterface simulator, int amount){
        //-----------------------------SEND TRANSACTION DATA---------------------------------------------------
        // Create signature amount || terminalCounter
        byte[] amountBytes = utils.intToShortBytes(amount);
        byte[] data = new byte[4];
        System.arraycopy(amountBytes, 0, data, 0, 2);
        System.arraycopy(terminalCounter, 0, data, 2, 2);

        byte[] transactionSignature = new byte[128];
        try {
            transactionSignature = utils.sign(data, terminalPrivKey);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();
        }

        // Send amount (2 bytes) || terminalCounter (2 bytes) || transactionSignature (128 bytes)
        byte[] dataToSend = new byte[132];
        System.arraycopy(amountBytes, 0, dataToSend, 0, 2);
        System.arraycopy(terminalCounter, 0, dataToSend, 2, 2);
        System.arraycopy(transactionSignature, 0, dataToSend, 4, 128);

        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x00, dataToSend);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // Increment terminalCounter 
        terminalCounter = utils.incrementCounter(terminalCounter);

        //-----------------------------RECEIVE TRANSACTION RESPONSE---------------------------------------------------
        // Get response from card:  M (1 byte) || signature (128 bytes)
        byte[] responseData = response.getData();
        byte M = responseData[0];
        byte[] signatureResponse = new byte[128];
        System.arraycopy(responseData, 1, signatureResponse, 0, 128);

        // Verify the signature using own terminalCounter incrementented by 1
        byte[] dataToVerify = new byte[3];
        System.arraycopy(responseData, 0, dataToVerify, 0, 1);
        System.arraycopy(terminalCounter, 0, dataToVerify, 1, 2);
       
        // Debug print terminalCounterResponse
        System.out.println("(reloadTerminal) Terminal Counter Response: " + utils.shortBytesToInt(terminalCounter));

        try {
            boolean verified = utils.verify(dataToVerify, signatureResponse, cardPubKey);
            System.out.println("(reloadTerminal) Transaction Signature verified: " + verified);

            if(M == 0){
                System.out.println("(reloadTerminal) RELOAD FAILED: ABORTING TRANSACTION");
            } else {
                System.out.println("(reloadTerminal) RELOAD SUCCESSFUL: TRANSACTION COMPLETED");

                // Write transactionSignature || signatureResponse to file under logs folder with timestamp
                utils.writeTransactionToLog(transactionSignature, signatureResponse);
            }
            
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }
    }
}