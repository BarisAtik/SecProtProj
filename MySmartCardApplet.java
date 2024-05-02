package epurse;

import javacard.framework.*;

public class MySmartCardApplet extends Applet {
    // Constants and variables for card initialization
    private static final byte CARD_ID_LENGTH = 8;
    private static final byte EXPIRY_DATE_LENGTH = 4;

    // Constants and variables for card state (e.g., balance, expiry date)
    private static short balance;
    private static short counter; 

    // Constants and variables for cryptographic keys
    private static final short RSA_KEY_LENGTH = 1024;
    
    // Initialization method
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // Generate and store unique card ID
        byte[] cardID = new byte[CARD_ID_LENGTH]; // You need to implement the generation of a unique card ID here

        // Generate and store cryptographic keys


        // Write expiry date to card
        writeExpiryDate();

        // Set balance of card
        balance = 0;

        // Initialize counter (nonce)
        counter = 0;

        // Generate and store private and public key of the card (RSA keys)


        // Store master public key (RSA key). Create the keypair outside this code and hardcode it to this code

        
    }
    
    // Method to write expiry date to card


    public boolean checkDate() {
        currentDate = ;
        expireDateCard = ;

        // Three if statements in eachother 
        if(currentDate[year]<=expireDateCard[year]) {
            if(currentDate[month]<=expireDateCard[month]){
                if(currentDate[day]<=expireDateCard[day]){
                    return true;
                }
            }
        } 
        return false;
    }

    // Selection method
    public boolean select() {
        // Return true to indicate that the applet is selectable
        // maybe POS or Reload selection, this is just a normal function that you can call, use it as you wish, can also be a function to clear everything (The end of transaction)
        // NOT REQUIRED TO USE IT
        // Probably use it for checking if card is expired
    }

    
    // Expiration date check function
    private boolean expireDate() {
        // Implement your expiration date check logic here
        // Compare the current date with the expiration date stored on the card
        // Return true if the card is not expired, false if it is expired
    }
    
    // Processing method
    public void process(APDU apdu) {
        // Handle different APDU commands based on lifecycle phases
        // Example: Process commands for adding funds, spending funds, checking balance, etc.

        // Get the buffer with the APDU data
        byte[] apduBuffer = apdu.getBuffer();
        
        // Check the INS byte to determine the command type
        byte ins = apduBuffer[OFFSET_INS];

        // STATE:
        // 0: when card isn't authenticated and expire date checked yet, after authentication + checkdate is complete set STATE to 1
        // 1: when card is authenticated and valid, it gets access to perform transactions
        // 2: when anything goes wrong, go to this STATE


        // Instructions
        // 00: check certificate and send challenge
        // 01: check response and send authentication request
        // 02: sign challenge and send response and counter
        // 03: check expire date
        // 04: 

        switch (STATE) {
            case 0:
            // Authentication + check date
                switch (ins) {
                    case 00:
                        validTerminal = checkCertificate(apduBuffer, apduBuffer);

                        if (validTerminal) {
                            STATE = 0;

                            // Send challenge

                        } else {
                            STATE = 2;
                        }
                        break;
                    case 01:
                        responseVerified = checkResponse(apduBuffer, apduBuffer);

                        if (responseVerified) {
                            STATE = 0;

                            // Send authentication request

                        } else {
                            STATE = 2;
                        }
                        break;
                    case 02:
                        signature = signChallenge(apduBuffer, apduBuffer);
                        
                        // send response and counter
                        
                        break;
                    case 03:
                        cardNotExpired = checkDate();

                        if (cardNotExpired){
                            terminalType = checkTerminalType(apduBuffer);
                            STATE = 1;
                        } else{
                            STATE = 2;
                        }
                        break;
                   
                    default:
                        break;
                }
                break;
            
            case 1:
            // Can perform transactions
                switch (terminalType) {
                    case "reload":
                        switch (ins) {
                            case 04:
                                
                                break;
                        
                            default:
                                break;
                        }
                        break;

                    case "POS":
                        
                        break;

                    default:
                        break;
                }
                break;
            
            case 2:
                
                break;
        
            default:
                break;
        }

    }

    private boolean checkCertificate(byte[] ID, byte[] publicKey){
        // RSA API 
    }

    private boolean checkResponse(byte[] challenge, byte[] counter){
        // RSA API
    }
    private byte[] signChallenge(byte[] challenge, byte[] counter){
        // Implement challenge signing logic
        // Use the terminal's private key to sign the challenge
        // Return the signed challenge
    }
    private byte[] checkTerminalType(byte[] terminalID){
        // check if the terminal is POS or Reload
    }

}