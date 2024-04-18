package epurse;

import javacard.framework.*;

public class MySmartCardApplet extends Applet {
    // Constants and variables for card initialization
    private static final byte CARD_ID_LENGTH = 8;
    private static final byte EXPIRY_DATE_LENGTH = 4;

    // Constants and variables for card state (e.g., balance, expiry date)
    private static short balance;

    // Constants and variables for cryptographic keys
    private static final short RSA_KEY_LENGTH = 1024;
    
    // Initialization method
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // Generate and store unique card ID
        byte[] cardID = new byte[CARD_ID_LENGTH]; // You need to implement the generation of a unique card ID here

        // Generate and store cryptographic keys


        // Write expiry date to card


        // Set balance of card
        balance = 0;

        // Initialize counter (nonce)


        // Generate and store private and public key of the card (RSA keys)


        // Store master public key (RSA key). Create the keypair outside this code and hardcode it to this code

        
    }
    
    // Selection method
    public boolean select() {
        // Return true to indicate that the applet is selectable
        // maybe POS or Reload selection, this is just a normal function that you can call, use it as you wish, can also be a function to clear everything (The end of transaction)
        // NOT REQUIRED TO USE IT
        // Probably use it for checking if card is expired


        if (checkDate()){ // GIVE TO THE FUNCTION THE DATES
            return true;
        } else {
            return false;
        }
    }
    
    // Processing method
    public void process(APDU apdu) {
        // Handle different APDU commands based on lifecycle phases
        // Example: Process commands for adding funds, spending funds, checking balance, etc.
 
        // If select() is True the card can be used, if false the card is expired  and not usable.
        if select(){
            // Switch case for switching between Reload and PoS terminal
            switch (state) {
                case 1: // Reload 
                    // The protocols

                    break;
                case 2: // POS
                    // The protocols

                    break;
                default:
                    // Use for default a blocked card

                    break;
            }
        } else {
            // 
        }
    }

    // Make the functions (your protocols) here such as: Authenticate, SignForReload, SignForPOS, Reload, POSOnline, POSOffline
    
    public boolean checkDate(currentDate, expireDateCard) {
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
}