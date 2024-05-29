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
import terminal.InitTerminal;
import terminal.Utils;
import terminal.POSTerminal;

public class Terminal {

    private final Utils utils;

    public Terminal() {
        utils = new Utils();
    }


    public void main(String[] arg) {
        Terminal main = new Terminal();
        // Initialize simulator -- Connect to the applet
        JavaxSmartCardInterface simulator = new JavaxSmartCardInterface();
        main.utils.selectApplet(simulator);

        // INITIALIZATION PHASE
        InitTerminal backend = new InitTerminal();
        backend.setMasterKeyPair();
        backend.sendCardIDAndExpireDate(simulator);
        backend.sendMasterPublicKey(simulator, backend.masterPublicKey);
        backend.createCertificate(simulator, backend.masterPrivateKey);
        
        byte[] POSCert = backend.getPOSCertificate();
        int POSTerminalID = backend.getPOSTerminalID(); 
        POSTerminal terminal = new POSTerminal(123);

    }
    
}
