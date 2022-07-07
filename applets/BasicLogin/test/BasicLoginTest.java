import com.licel.jcardsim.smartcardio.*;
import javax.smartcardio.*;
import com.licel.jcardsim.utils.*;

import BasicLogin.BasicLoginApplet;
import javacard.framework.*;

import static org.junit.Assert.*;
import org.junit.Test;
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import org.junit.jupiter.api.Test;

import BasicLogin.BasicLoginApplet;

public class BasicLoginTest {
    
    @Test
    void basicLogin() {
        // 1. Create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. Install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, BasicLoginApplet.class);

        // 3. Select applet
        simulator.selectApplet(appletAID);

        // 4. Send APDU
        CommandAPDU commandAPDU = new CommandAPDU(0, 1 << 3, 0, 0);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // 5. Check response status word
        assertEquals(0x9000, response.getSW());
        System.out.print("Tested");
    }
}