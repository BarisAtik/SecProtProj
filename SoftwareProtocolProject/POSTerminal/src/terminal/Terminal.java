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
        
        POSTerminal POSterminal = new POSTerminal(123, backend.masterPublicKey);
        POSterminal.setTerminalKeyPair();
        byte[] terminalCert = backend.createTerminalCertificate(POSterminal.terminalID, POSterminal.terminalPubKey, backend.masterPrivateKey);
        POSterminal.setTerminalCertificate(terminalCert);

        reloadTerminal reloadTerminal = new reloadTerminal(223, backend.masterPublicKey);
        reloadTerminal.setTerminalKeyPair();
        byte[] reloadTerminalCert = backend.createTerminalCertificate(reloadTerminal.terminalID, reloadTerminal.terminalPubKey, backend.masterPrivateKey);
        reloadTerminal.setTerminalCertificate(reloadTerminalCert);

        // DEMO
        boolean demo = true;
        while(demo){
            Scanner scanner = new Scanner(System.in);
            System.out.println("Choose an option: ");
            System.out.println("1) Pay at a POSterminal");
            System.out.println("2) Reload card at a reload terminal");
            System.out.println("3) Check balance");
            int option = scanner.nextInt();
            switch(option){
                case 1:
                    POSterminal.authenticateCard(simulator);
                    if(!main.cardBlocked(simulator)){
                        System.out.println("Enter amount in eurocents (123 -> 1,23 EUR): ");
                        int amount = scanner.nextInt();

                        if(!(amount > 30000 || amount < 0)){
                            System.out.println("Amount: " + main.utils.amountToString(amount) + " EUR");
                            POSterminal.performTransaction(simulator, amount);
                        } else {
                            System.out.println("Invalid amount or amount exceeds maximum amount (300 EUR)");
                        }

                    } else {
                        System.err.println("Card is blocked");
                        demo = false;
                    }
                    break; 
                case 2:
                    reloadTerminal.authenticateCard(simulator);
                    if(!main.cardBlocked(simulator)){
                        int balance = backend.getBalance(simulator);
                        int maximumReloadAmount = 30000 - balance;
                        System.out.println("Enter amount to reload in eurocents (max: " + main.utils.amountToString(maximumReloadAmount) + "): ");
                        int reloadAmount = scanner.nextInt();

                        if(!(reloadAmount > maximumReloadAmount || reloadAmount < 0)){
                            main.talkToBank(scanner);   
                            reloadTerminal.performReload(simulator, reloadAmount);
                        } else {
                            System.out.println("Invalid amount or amount exceeds maximum reload amount (300 EUR)");
                        }

                    } else {
                        System.err.println("Card is blocked");
                        demo = false;
                    }
                    break;
                case 3: 
                    System.out.println("Balance on the card: " + main.utils.amountToString(backend.getBalance(simulator)) + " EUR");
                    break;
                default:
                    System.out.println("Invalid option");
                    demo = false;
                    break;
            }
        }
    }

    /**
     * A simulation of a terminal talking to a bank for demonstration purposes.
     * 
     * @param scanner
     */
    private void talkToBank(Scanner scanner){
        String[] bank = {"ING", "ABN", "Rabobank"};
        System.out.println("Choose a bank: ");
        for(int i = 0; i < bank.length; i++){
            System.out.println((i+1) + ") " + bank[i]);
        }
        int bankChoice = scanner.nextInt();
        System.out.println("Talkin to " + bank[bankChoice - 1]);   
        System.out.println("Enter PIN");
        int pin = scanner.nextInt();
        System.out.println("Bank response: OK");
    }

    /**
     * This function is only for demonstration purposes because we use a simulator. The card sends only a boolean to the terminal to indicate if the card is blocked. 
     * With the simulator, if a card is blocked, it will throw a ISOException with the status word SW_CONDITIONS_NOT_SATISFIED but we can't catch this exception in the simulator.
     * 
     * @param simulator
     * @return true if card is blocked, false if not
     */
    private boolean cardBlocked(JavaxSmartCardInterface simulator){
        // Try silly command to see if card is blocked
        CommandAPDU commandAPDU = new CommandAPDU((byte) 0x00, (byte) 11, (byte) 0x00, (byte) 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        // Check if boolean is true
        if(response.getData()[0] == 1){
            return true;
        }
        return false;
    }
    
}
