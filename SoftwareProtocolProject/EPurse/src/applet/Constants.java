package applet;

public class Constants {
    public final static short ID_size = 4;
    public final static short EXPIREDATE_size = 4;  // Unix time
    public final static short BALANCE_SIZE = 2;
    public final static short COUNTER_SIZE = BALANCE_SIZE;


    public final static short NONCE_SIZE = 4; 
    public final static short EXPONENT_SIZE = 3;
    public final static short SIGNATURE_SIZE = 128;
    public final static short KEY_SIZE = 128;

    // Card states
    public final static byte STATE_DATA_EXCHANGED = 0x01;
    public final static byte STATE_CERTIFICATE_EXCHANGED = 0x02;
    public final static byte STATE_AUTHENTICATED = 0x03;


}
