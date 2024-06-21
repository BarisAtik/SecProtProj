package terminal;

import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;

import javax.smartcardio.*;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;

import com.licel.jcardsim.io.JavaxSmartCardInterface; 
import com.licel.jcardsim.smartcardio.JCardSimProvider; 
import com.licel.jcardsim.smartcardio.CardTerminalSimulator;
import com.licel.jcardsim.smartcardio.CardSimulator;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import applet.EPurse;

public class Utils {
    static final byte[] EPURSE_APPLET_AID = { (byte) 0x3B, (byte) 0x29,
        (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };
    static final String EPURSE_APPLET_AID_string = "3B2963616C6301";
    static final CommandAPDU SELECT_APDU = new CommandAPDU(
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, EPURSE_APPLET_AID);

    
    public void selectApplet(JavaxSmartCardInterface simulator){
        AID EPURSE_AppletAID = new AID(EPURSE_APPLET_AID,(byte)0,(byte)7);
        simulator.installApplet(EPURSE_AppletAID, EPurse.class);

        CommandAPDU SELECT_APDU = new CommandAPDU( (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,EPURSE_APPLET_AID);
        ResponseAPDU response = simulator.transmitCommand(SELECT_APDU);
    }

    public void sendCommandToApplet(JavaxSmartCardInterface simulator, int command){
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) command, (byte) 0x00, (byte) 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        //System.out.println("Response: " + toHexString(response.getBytes()));
    }

    public int getBalance(JavaxSmartCardInterface simulator){
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x09, (byte) 0x00, (byte) 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        byte[] responseData = response.getData();
        return shortBytesToInt(responseData);
    }

    public String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
          sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public byte[] getCurrentDate() {
        Instant now = Instant.now();
        int currentUnixTimestamp = (int) now.getEpochSecond();

        return intToBytes(currentUnixTimestamp);
    }

    /*
     * Compares two dates represented as byte arrays
     * Returns true if date1 is before date2
     * Returns false otherwise
     * 
     */
    public boolean isPastDate(byte[] date, byte[] currentDate) {
        return bytesToInt(date) < bytesToInt(currentDate);
    }

    public byte[] intToBytes(int i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(i);
        return bb.array();
    }

    public int bytesToInt(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return bb.getInt();
    }

    public int shortBytesToInt(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return bb.getShort();
    }

    public byte[] intToShortBytes(int i){
        ByteBuffer bb = ByteBuffer.allocate(2);
        bb.putShort((short) i);
        return bb.array();
    }

    public byte[] incrementByteArray(byte[] array){
        ByteBuffer bb = ByteBuffer.wrap(array);
        int value = bb.getInt();
        value++;
        bb.putInt(value);
        return bb.array();
    }

    // Function to increment byte[2] counter using ByteBuffer
    public byte[] incrementCounter(byte[] counter){
        short counterValue = ByteBuffer.wrap(counter).getShort();
        counterValue++;
        ByteBuffer.wrap(counter).putShort(counterValue);
        return counter;
    }

    public RSAPublicKey getPublicKey(byte[] exponent, byte[] modulus) throws NoSuchAlgorithmException, InvalidKeySpecException {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(1, modulus), new BigInteger(1, exponent));
        return (RSAPublicKey) keyFactory.generatePublic(keySpec);
    }

    public byte[] sign(byte[] content, RSAPrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA1WithRSA");
        signer.initSign(key);
        signer.update(content);
        return signer.sign();
    }

    public boolean verify(byte[] content, byte[] signature, RSAPublicKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature verifier = Signature.getInstance("SHA1WithRSA");
        verifier.initVerify(key);
        verifier.update(content);
        return verifier.verify(signature);
    }

    public void writeTransactionToLog(byte[] transactionSignature, byte[] responseSignature, byte[] cardID, int terminalID, int amount){
        String fileName = "logs/transaction_" + LocalDateTime.now().toString() + ".txt";
        try {
            FileWriter fileWriter = new FileWriter(fileName);
            fileWriter.write("Transaction Date: " + LocalDateTime.now().toString() + "\n");
            fileWriter.write("Card ID: " + bytesToInt(cardID) + "\n");
            fileWriter.write("Terminal ID: " + terminalID + "\n");
            fileWriter.write("Amount: " + amountToString(amount) + " EUR" +"\n");
            fileWriter.write("Transaction Signature: " + Base64.getEncoder().encodeToString(transactionSignature) + "\n");
            fileWriter.write("Response Signature: " + Base64.getEncoder().encodeToString(responseSignature) + "\n");
            fileWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public String amountToString(int amount){
        String amountString = Integer.toString(amount);
        if(amountString.length() == 1){
            amountString = "0,0" + amountString;
        } else if(amountString.length() == 2){
            amountString = "0," + amountString;
        } else {
            amountString = amountString.substring(0, amountString.length() - 2) + "," + amountString.substring(amountString.length() - 2);
        }
        return amountString;
    }
 }
