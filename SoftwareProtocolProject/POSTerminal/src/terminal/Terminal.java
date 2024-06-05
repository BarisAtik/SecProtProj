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
import java.util.Scanner;

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
import terminal.reloadTerminal;

public class Terminal {

    private final Utils utils;

    public Terminal() {
        utils = new Utils();
    }


    public static void main(String[] arg) {
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
        
        int terminalID = 123;

        POSTerminal POSterminal = new POSTerminal(123, backend.masterPublicKey);
        POSterminal.setTerminalKeyPair();
        byte[] terminalCert = backend.createTerminalCertificate(POSterminal.terminalID, POSterminal.terminalPubKey, backend.masterPrivateKey);
        POSterminal.setTerminalCertificate(terminalCert);

        reloadTerminal reloadTerminal = new reloadTerminal(023, backend.masterPublicKey);
        reloadTerminal.setTerminalKeyPair();
        byte[] reloadTerminalCert = backend.createTerminalCertificate(reloadTerminal.terminalID, reloadTerminal.terminalPubKey, backend.masterPrivateKey);
        reloadTerminal.setTerminalCertificate(reloadTerminalCert);

        // Scanner object to read input from user
        // 0) Pay at a POSterminal
        // 1) Reload card
        // 2) Check balance
        
        boolean demo = true;
        while(demo){
            Scanner scanner = new Scanner(System.in);
            System.out.println("Choose an option: ");
            System.out.println("0) Pay at a POSterminal");
            System.out.println("1) Reload card at a reload terminal");
            System.out.println("2) Check balance");
            int option = scanner.nextInt();
            switch(option){
                case 0:
                    POSterminal.authenticateCard(simulator);
                    // Ask for amount
                    System.out.println("Enter amount: ");
                    int amount = scanner.nextInt();
                    POSterminal.performTransaction(simulator, amount);
                    break;
                case 1:
                    reloadTerminal.authenticateCard(simulator);
                    int balance = backend.getBalance(simulator);
                    int maximumReloadAmount = 500 - balance;
                    System.out.println("Enter amount to reload (max: " + maximumReloadAmount + "): ");
                    int reloadAmount = scanner.nextInt();
                    if(reloadAmount > maximumReloadAmount || reloadAmount < 0){
                        System.out.println("Invalid amount");
                        break;
                    }
                    reloadTerminal.performReload(simulator, reloadAmount);
                    break;
                case 2: 
                    System.out.println("Balance on the card: " + backend.getBalance(simulator));
                    break;
                default:
                    System.out.println("Invalid option");
                    demo = false;
                    break;
            }
        }
        //POSterminal.authenticateCard(simulator);
        //POSterminal.performTransaction(simulator, 50);

    }
    
}
