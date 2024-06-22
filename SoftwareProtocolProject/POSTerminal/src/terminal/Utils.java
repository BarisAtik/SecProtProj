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

    
    
    /**
     * Selects the EPurse applet on the simulator
     * @param simulator
     */
    public void selectApplet(JavaxSmartCardInterface simulator){
        AID EPURSE_AppletAID = new AID(EPURSE_APPLET_AID,(byte)0,(byte)7);
        simulator.installApplet(EPURSE_AppletAID, EPurse.class);

        CommandAPDU SELECT_APDU = new CommandAPDU( (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00,EPURSE_APPLET_AID);
        ResponseAPDU response = simulator.transmitCommand(SELECT_APDU);
    }

    /**
     * Sends a command to the applet on the simulator
     * 
     * @param simulator
     * @param command
     */
    public void sendCommandToApplet(JavaxSmartCardInterface simulator, int command){
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) command, (byte) 0x00, (byte) 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        //System.out.println("Response: " + toHexString(response.getBytes()));
    }

    /**
     * Retrieves the current balance from the smart card.
     *
     * This method sends a command APDU to the smart card to request the current balance. The balance is expected
     * to be returned as a 2-byte array which is then converted to an integer.
     *
     * @param simulator The {@link JavaxSmartCardInterface} instance used to communicate with the smart card.
     * @return The current balance stored on the smart card, converted from a 2-byte array to an integer.
     */
    public int getBalance(JavaxSmartCardInterface simulator){
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 0x09, (byte) 0x00, (byte) 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        byte[] responseData = response.getData();
        return shortBytesToInt(responseData);
    }

    /**
     * Converts a byte array to a hex string representation
     * 
     * @param bytes A byte array
     * @return A hex string representation of the byte array
     */
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

    /**
     * Checks if a given date is before the current date.
     * 
     * This method compares two byte arrays representing dates. The first byte array represents the date to check,
     * and the second byte array represents the current date. Both dates are expected to be in a format that can
     * be converted to an integer timestamp. The method returns true if the first date is before the second date.
     * 
     * @param date The byte array representing the date to check.
     * @param currentDate The byte array representing the current date.
     * @return true if the date represented by the first byte array is before the date represented by the second byte array; false otherwise.
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

    /**
     * Converts a byte array to a int
     * 
     * @param bytes
     * @return An integer representing the byte array
     */
    public int shortBytesToInt(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.wrap(bytes);
        return bb.getShort();
    }

    /**
     * Converts an integer to a byte array of length 2 (short)
     * 
     * @param i The integer to convert
     * @return A byte array of length 2 representing the integer
     */
    public byte[] intToShortBytes(int i){
        ByteBuffer bb = ByteBuffer.allocate(2);
        bb.putShort((short) i);
        return bb.array();
    }

    /**
     * Converts a byte array represting an integer of size 4
     * 
     * @param bytes
     * @return Byte array incremented by 1 with size 4
     */
    public byte[] incrementByteArray(byte[] array){
        ByteBuffer bb = ByteBuffer.wrap(array);
        int value = bb.getInt();
        value++;
        bb.putInt(value);
        return bb.array();
    }

    /**
     * Increments a counter (2 bytes) represented by a byte array
     * 
     * @param counter
     * @return The incremented counter as a byte array
     */
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
    /**
     * Converts an integer amount to a string representation in euros.
     * 
     * This method takes an integer amount, representing the total cents, and formats it as a string in euro currency format.
     * For example, an input of 12345 would be converted to "123,45", representing 123 euros and 45 cents.
     * If the amount is less than 10 cents, it prefixes with "0,0", and if it is less than 1 euro but 10 cents or more,
     * it prefixes with "0,". This ensures the string always represents a valid euro amount.
     * 
     * @param amount The amount in cents to be converted to a string representation.
     * @return A string representing the amount in euros, formatted correctly with a comma separating euros and cents.
     */
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
