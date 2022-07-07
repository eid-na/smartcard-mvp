import com.licel.jcardsim.smartcardio.*;
import javax.smartcardio.*;
import com.licel.jcardsim.utils.*;
import javacard.framework.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.junit.jupiter.api.Test;

import openpgpcard.OpenPGPApplet;

public class pgpTest {
    
    @Test
    void checkVersion() {
        // 1. Create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. Install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, OpenPGPApplet.class);

        // 3. Select applet
        simulator.selectApplet(appletAID);

        // 4. Send APDU
        CommandAPDU commandAPDU = new CommandAPDU((byte)0x00, (byte)0xF1, (byte)0x00, (byte)0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        System.out.println(response.toString());

        // 5. Check response status word
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());
    }
}