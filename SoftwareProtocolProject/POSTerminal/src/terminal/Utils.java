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
import java.util.Base64;
import java.util.List;

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
        System.out.println("Response: " + toHexString(response.getBytes()));
    }

    public String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b: bytes) {
          sb.append(String.format("%02X ", b));
        }
        return sb.toString();
    }

    public byte[] intToBytes(int i) {
        ByteBuffer bb = ByteBuffer.allocate(4);
        bb.putInt(i);
        return bb.array();
    }

    public byte[] sign(byte[] content, RSAPrivateKey key) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signer = Signature.getInstance("SHA1withRSA");
        signer.initSign(key);
        signer.update(content);
        return signer.sign();
    }
    
    public RSAPublicKey readX509PublicKey() {
        RSAPublicKey publicKey = null;
        try {
            // Read the PEM file
            String pemFile = "/home/parallels/SecProtProj/SoftwareProtocolProject/POSTerminal/src/terminal/PublicMasterKey.pem";
            List<String> lines = Files.readAllLines(Paths.get(pemFile));
            // Remove the first and last lines
            lines.remove(0);
            lines.remove(lines.size() - 1);
            // Concatenate the remaining lines to a single String
            String key = String.join("", lines);
            // Decode the base64 String to a byte array
            byte[] decodedKey = Base64.getDecoder().decode(key);
            // Convert the byte array to a PublicKey
            X509EncodedKeySpec spec = new X509EncodedKeySpec(decodedKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            publicKey = (RSAPublicKey) kf.generatePublic(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    public RSAPrivateKey readPKCS8PrivateKey() {
        RSAPrivateKey privateKey = null;
        try {
            // Read the PEM file
            String filePath = "/home/parallels/SecProtProj/SoftwareProtocolProject/POSTerminal/src/terminal/PrivateMasterKey2.pem";
            String key = new String(Files.readAllBytes(Paths.get(filePath)));
        
            // Remove the PEM headers and footers
            key = key.replace("-----BEGIN RSA PRIVATE KEY-----", "")
                    .replace("-----END RSA PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");  // Remove all whitespace characters

            // Decode the base64 String to a byte array
            byte[] encodedPrivateKey = Base64.getDecoder().decode(key);;
            // Convert the byte array to a PublicKey
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(encodedPrivateKey);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            privateKey = kf.generatePrivate(spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return privateKey;
    }
}
