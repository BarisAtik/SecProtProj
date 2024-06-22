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
        terminalCert = new byte[Constants.SIGNATURE_SIZE];
        this.terminalID = terminalID;
        this.masterPubKey = masterPubKey;

        cardID = new byte[Constants.ID_size];
        cardNonce = new byte[Constants.NONCE_SIZE];
        cardExpireDate = new byte[Constants.EXPIREDATE_size];
        cardExp = new byte[Constants.EXPONENT_SIZE];
        cardMod = new byte[Constants.KEY_SIZE];
        cardCertificate = new byte[Constants.SIGNATURE_SIZE];

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

        System.arraycopy(terminalIDBytes, 0, data, 0, Constants.ID_size);
        System.arraycopy(terminalNonce, 0, data, Constants.ID_size, Constants.NONCE_SIZE);
        System.arraycopy(terminalExponent, 0, data, (Constants.ID_size + Constants.NONCE_SIZE), Constants.EXPONENT_SIZE);
        System.arraycopy(terminalModulus, 0, data, (Constants.ID_size + Constants.NONCE_SIZE + Constants.EXPONENT_SIZE), Constants.KEY_SIZE);

        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, data);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        //-----------------------------RECEIVE CARD DATA---------------------------------------------------

        // Receive cardID (4 bytes)|| cardNonce (4 bytes) || cardExpireDate (4 bytes) || cardExp (3 bytes)|| cardMod (128 bytes)
        byte[] responseData = response.getData();
        System.arraycopy(responseData, 0, cardID, 0, Constants.ID_size);
        System.arraycopy(responseData, Constants.ID_size, cardNonce, 0, Constants.NONCE_SIZE);
        System.arraycopy(responseData, (Constants.ID_size + Constants.NONCE_SIZE), cardExpireDate, 0, Constants.EXPIREDATE_size);
        System.arraycopy(responseData, (Constants.ID_size + Constants.NONCE_SIZE + Constants.EXPIREDATE_size), cardExp, 0, Constants.EXPONENT_SIZE);
        System.arraycopy(responseData, (Constants.ID_size + Constants.NONCE_SIZE + Constants.EXPIREDATE_size + Constants.EXPONENT_SIZE), cardMod, 0, Constants.KEY_SIZE);

        // Make the public key of the card from the cardMod and the cardExp using setExponent and setModulus
       try {
            cardPubKey = utils.getPublicKey(terminalExponent, cardMod);
       } catch (Exception e) {
            e.printStackTrace();
       }

        // Terminal sends Certificate to card
        CommandAPDU commandAPDU2 = new CommandAPDU((byte) 0x00, (byte) 0x05, (byte) 0x00, (byte) 0x00, terminalCert);
        ResponseAPDU response2 = simulator.transmitCommand(commandAPDU2);

        byte[] response2Data = response2.getData();
        System.arraycopy(response2Data, 0, cardCertificate, 0, Constants.SIGNATURE_SIZE);

        // Verify contents with the certificate
        byte[] dataToVerify = new byte[Constants.CERTIFICATE_SIZE];
        System.arraycopy(cardID, 0, dataToVerify, 0, Constants.ID_size);
        System.arraycopy(cardExpireDate, 0, dataToVerify, Constants.ID_size, Constants.EXPIREDATE_size);
        System.arraycopy(cardExp, 0, dataToVerify, (Constants.ID_size + Constants.EXPIREDATE_size), Constants.EXPONENT_SIZE);
        System.arraycopy(cardMod, 0, dataToVerify, (Constants.ID_size + Constants.EXPIREDATE_size + Constants.EXPONENT_SIZE), Constants.KEY_SIZE);

        try {
            boolean verified = utils.verify(dataToVerify, cardCertificate, masterPubKey);
            System.out.println("(POSTerminal) Certificate verified: " + verified);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }

        //-----------------------------SIGN CARD NONCE---------------------------------------------------
        
        // sign and send signed nonce to card
        byte[] cardNonceSignature = new byte[Constants.SIGNATURE_SIZE];
        try {
            cardNonceSignature = utils.sign(cardNonce, terminalPrivKey);
            // System.out.println("(POSTerminal) cardNonceSignature size: " + cardNonceSignature.length); 
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
            System.out.println("(POSTerminal) Terminal Nonce Signature verified: " + verified);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }

        //------------------------------CHECK EXPIRY DATE--------------------------------------------------
        // Check if the card is expired 
        byte[] currentDate = utils.getCurrentDate();
        byte[] expireDate = new byte[Constants.EXPIREDATE_size];
        System.arraycopy(cardExpireDate, 0, expireDate, 0, Constants.EXPIREDATE_size);

        if(utils.isPastDate(expireDate, currentDate)){
            System.out.println("(POSTerminal) Card is expired!");
        } else {
            System.out.println("(POSTerminal) Card is not expired!");
        }

        // If card is expired, send command to block the card
        if(utils.isPastDate(expireDate, currentDate)){
            // sign cardId 
            byte[] signature = new byte[Constants.SIGNATURE_SIZE];
            try {
                signature = utils.sign(cardID, terminalPrivKey);
            } catch (Exception e) {
                // Handle the exception here
                e.printStackTrace();
            }
            // Send signature to card
            System.out.println("(POSTerminal) Sending blocking command to card");
            CommandAPDU commandAPDU4 = new CommandAPDU((byte) 0x00, (byte) 10, (byte) 0x00, (byte) 0x00, signature);
            ResponseAPDU response4 = simulator.transmitCommand(commandAPDU4);
        }
    }

    public void performReload(JavaxSmartCardInterface simulator, int amount){
        //-----------------------------SEND TRANSACTION DATA---------------------------------------------------
        // Check if terminalCounter is not SIGNED_SHORT_MAX_VALUE (prevent overflow on card side)
        if(terminalCounter[0] == 0x7F && terminalCounter[1] == 0xFF){
            terminalCounter = new byte[]{0x00, 0x00};
        }

        // Create signature amount || terminalCounter
        byte[] amountBytes = utils.intToShortBytes(amount);
        byte[] data = new byte[(Constants.BALANCE_SIZE + Constants.COUNTER_SIZE)];
        System.arraycopy(amountBytes, 0, data, 0, Constants.BALANCE_SIZE);
        System.arraycopy(terminalCounter, 0, data, Constants.BALANCE_SIZE, Constants.COUNTER_SIZE);

        byte[] transactionSignature = new byte[Constants.SIGNATURE_SIZE];
        try {
            transactionSignature = utils.sign(data, terminalPrivKey);
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();
        }

        // Send amount (2 bytes) || terminalCounter (2 bytes) || transactionSignature (128 bytes)
        byte[] dataToSend = new byte[(Constants.BALANCE_SIZE + Constants.COUNTER_SIZE + Constants.SIGNATURE_SIZE)];
        System.arraycopy(amountBytes, 0, dataToSend, 0, Constants.BALANCE_SIZE);
        System.arraycopy(terminalCounter, 0, dataToSend, Constants.BALANCE_SIZE, Constants.COUNTER_SIZE);
        System.arraycopy(transactionSignature, 0, dataToSend, (Constants.BALANCE_SIZE + Constants.COUNTER_SIZE), Constants.SIGNATURE_SIZE);

        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x08, (byte) 0x00, (byte) 0x00, dataToSend);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // Increment terminalCounter 
        terminalCounter = utils.incrementCounter(terminalCounter);

        //-----------------------------RECEIVE TRANSACTION RESPONSE---------------------------------------------------
        // Get response from card:  M (1 byte) || signature (128 bytes)
        byte[] responseData = response.getData();
        byte M = responseData[0];
        byte[] signatureResponse = new byte[Constants.SIGNATURE_SIZE];
        System.arraycopy(responseData, 1, signatureResponse, 0, Constants.SIGNATURE_SIZE);

        // Verify the signature using own terminalCounter incrementented by 1
        byte[] dataToVerify = new byte[(1 + Constants.COUNTER_SIZE)];
        System.arraycopy(responseData, 0, dataToVerify, 0, 1);
        System.arraycopy(terminalCounter, 0, dataToVerify, 1, Constants.COUNTER_SIZE);
       
        // Debug print terminalCounterResponse
        //System.out.println("(reloadTerminal) Terminal Counter Response: " + utils.shortBytesToInt(terminalCounter));

        try {
            boolean verified = utils.verify(dataToVerify, signatureResponse, cardPubKey);
            System.out.println("(reloadTerminal) Transaction Signature verified: " + verified);

            if(M == 0){
                System.out.println("(reloadTerminal) RELOAD FAILED: ABORTING TRANSACTION");
            } else {
                System.out.println("(reloadTerminal) RELOAD SUCCESSFUL: TRANSACTION COMPLETED");

                // Write transactionSignature || signatureResponse to file under logs folder with timestamp
                utils.writeTransactionToLog(transactionSignature, signatureResponse, cardID, terminalID, amount);
            }
            
        } catch (Exception e) {
            // Handle the exception here
            e.printStackTrace();   
        }
    }
}
