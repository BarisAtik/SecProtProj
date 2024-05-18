package applet;

import javacard.framework.*;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.Util;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import java.applet.Applet;
import java.nio.ByteBuffer;
import javacard.security.KeyBuilder;
import javacard.security.RSAPublicKey;
import javacard.security.Signature;

public class CardAuth {
    private final EPurse purse;

    public CardAuth(EPurse purse) {
        this.purse = purse;
    }

    public void Authenticate(APDU apdu){
        byte[] buffer = apdu.getBuffer();
    }
}
