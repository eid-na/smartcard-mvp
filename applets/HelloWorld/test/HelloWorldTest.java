import com.licel.jcardsim.smartcardio.*;
import javax.smartcardio.*;
import com.licel.jcardsim.utils.*;
import javacard.framework.*;

import static org.junit.Assert.*;
import org.junit.Test;
//import static org.junit.jupiter.api.Assertions.assertEquals;
//import org.junit.jupiter.api.Test;

import HelloWorld.HelloWorldApplet;

public class HelloWorldTest {
    
    @Test
    void helloWorld() {
        // 1. Create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. Install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, HelloWorldApplet.class);

        // 3. Select applet
        simulator.selectApplet(appletAID);

        // 4. Send APDU
        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x01, 0x00, 0x00);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);

        // 5. Check response status word
        assertEquals(0x9000, response.getSW());
    }
}