package terminal;

import javax.smartcardio.*;
import java.io.File;
import java.io.IOException;
import java.time.OffsetDateTime;

public abstract class Terminal {
    private static final byte[] APPLET_AID = { (byte) 0x3B, (byte) 0x29, (byte) 0x63, (byte) 0x61, (byte) 0x6C, (byte) 0x63, (byte) 0x01 };
    private static final CommandAPDU SELECT_AID = new CommandAPDU((byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, EPURSE_APPLET_AID);
    private CardTerminal terminal;

    Terminal() {
        try {
            var factory = TerminalFactory.getDefault();
            var terminals = factory.terminals();
            terminal = terminals.list().get(0);
        } catch (CardException e) {
            e.printStackTrace();
        }
    }


    private void selectApplet(CardChannel channel) throws CardException {
        var channel.transmit(SELECT_AID);
        if (channel.getSW() != 0x9000) {
            throw new CardException("Failed to select applet");
        }

    }
