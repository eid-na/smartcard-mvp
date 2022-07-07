package BasicLogin;

import java.security.KeyPairGenerator;

// import java.security.KeyPair;
// import java.security.KeyPairGenerator;
// import java.security.interfaces.ECKey;
// import java.security.interfaces.ECPublicKey;

import javacard.framework.*;
import javacard.security.*;
//import javacardx.crypto.*;

public class BasicLoginApplet extends Applet implements ISO7816 
{
    private byte canary                         = (byte)0x6969;
    private final byte maxPinSize               = 8;
    private final byte pinTryLimit              = 3;
    private final byte deselectMagic            = (byte)0x9696;
    private final byte VERSION[]                = {'I', '2', 'P', '_', 'M', 'V', 'P'};

    private final byte ENTER_PIN_INS            = 1 << 0;
    private final byte CHALLENGE_REQUEST_INS    = 1 << 1;
    private final byte CHALLENGE_RESPONSE_INS   = 1 << 2;
    private final byte GET_VERSION_INS          = 1 << 3;

    private byte[] initParamsBytes;
    //private OwnerPin Pin;
    private KeyPair keyPair;

    private byte[] deselectFlag;
    
    protected BasicLoginApplet(byte[] bArray, short bOffset, byte bLength) 
    {
        if (bLength > 0) {
            byte iLen       = bArray[bOffset]; // aid length
            
            bOffset         = (short) (bOffset + iLen + 1);
            byte cLen       = bArray[bOffset]; // info length
            
            bOffset         = (short) (bOffset + 3);
            byte aLen       = bArray[bOffset]; // applet data length
            
            initParamsBytes = new byte[aLen];
            Util.arrayCopyNonAtomic(bArray, (short) (bOffset + 1), initParamsBytes, (short) 0, aLen);
        }

      //  transientMemory = JCSystem.makeTransientByteArray(LENGTH_ECHO_BYTES, JCSystem.CLEAR_ON_RESET);
       // Pin             = new OwnerPIN(pinTryLimit, maxPinSize);
      //  deselectFlag    = JCSystem.makeTransientByteArray(1, JCSystem.CLEAR_ON_DESELECT);
      //  DoReset();

        register();
    }    


    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException 
    {
        new BasicLoginApplet(bArray, bOffset,bLength);
    }

    public void process(APDU apdu) 
    {
        if(selectingApplet())
            return;

       // ConditionalReset();
        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS])
        {
        //    case ENTER_PIN_INS:
        //        EnterPin(apdu);
        //        break;
        //    case CHALLENGE_REQUEST_INS:
        //        AuthenticateMe(apdu);
        //        break;
        //    case CHALLENGE_RESPONSE_INS:
        //        AuthenticateOther(apdu);
        //        break;
            case GET_VERSION_INS:
                getVersion(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    /*
    private bool CheckReset()
    {
        return deselectFlag[0] != deselectMagic;
    }

    private void DoReset()
    {
        Pin.setValidatedFlag(false);
        deselectFlag[0] = deselectMagic;
    }

    private void ConditionalReset()
    {
        if (CheckReset())
            DoReset();
    }

    private void RequireSession()
    {
        if (!Pin.isValidated())
            ISOExcepion.throwIt(ISO7816.SECURITY_STATUS_NOT_SATISFIED);
    }

    private void EnterPin(APDU apdu) throws ISOException
    {
        // Some stuff to get the PIN as a byte
    }

    private void AuthenticateMe(APDU apdu) throws ISOException
    {
        RequireSession();
        

        

    }

    private void AuthenticateOther(APDU apdu) throws ISOException
    {
        RequireSession();

        // Not yet implemented
        // Requires an authority certificate somewhere in read-only storage
    }
*/

    private void generateKeyPair(APDU apdu)
    {
        keyPair = new KeyPair(KeyPair.ALG_RSA, (short) 1024);
        keyPair.genKeyPair();

        /*
        keyPair = new KeyPair(
            (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false),
            (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false)
        );
        Secp256r1.setCommonCurveParameters( (ECKey) keyPair.getPrivate() );
        Secp256r1.setCommonCurveParameters( (ECKey) keyPair.getPublic() );

        */
    }

    private void getVersion(APDU apdu) throws ISOException
    {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(VERSION, (short)0, buffer, (short)0, (short)VERSION.length);
        apdu.setOutgoingAndSend((short)0, (short)VERSION.length);
    }

    private void getPublic(APDU apdu)
    {

    }


    /*
    private void sayHello(APDU apdu, short sw) {
        byte[]  buffer      = apdu.getBuffer(); // Here all bytes of the APDU are stored
        // receive all bytes if P1 = 0x01 (echo)
        short   incomeBytes = apdu.setIncomingAndReceive();
        byte[]  echo        = transientMemory;
        short   echoLength;
        if (buffer[ISO7816.OFFSET_P1] == 0x01) {
            echoLength = incomeBytes;
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, echo, (short) 0, incomeBytes);
        } else {
            echoLength = (short) helloMessage.length;
            Util.arrayCopyNonAtomic(helloMessage, (short) 0, echo, (short) 0, (short) helloMessage.length);
        }
        
        apdu.setOutgoing();                                 // Tell JVM that we will send data
        apdu.setOutgoingLength(echoLength);                 // Set the length of data to send
        apdu.sendBytesLong(echo, (short) 0, echoLength);    // Send our message starting at 0 position
        
        if(sw != (short) 0x9000) {                          // Set application specific sw
            ISOException.throwIt(sw);
        }
    }

    private void sayEcho2(APDU apdu) {
        byte buffer[]       = apdu.getBuffer();

        short bytesRead     = apdu.setIncomingAndReceive();
        short echoOffset    = (short) 0;

        while (bytesRead > 0) {
            Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, echoBytes, echoOffset, bytesRead);
            echoOffset += bytesRead;
            bytesRead   = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
        }

        apdu.setOutgoing();
        apdu.setOutgoingLength(echoOffset);
        apdu.sendBytesLong(echoBytes, (short) 0, echoOffset);   // echo data
    }

    private void sayIParams(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)initParamsBytes.length);
        apdu.sendBytesLong(initParamsBytes, (short) 0, (short)initParamsBytes.length);  // echo install parmas
    }   

    private void sayContinue(APDU apdu) {
        byte[]  echo        = transientMemory;
        short   echoLength  = (short) 6;
        Util.arrayCopyNonAtomic(helloMessage, (short)0, echo, (short)0, (short)6);
        apdu.setOutgoing();
        apdu.setOutgoingLength(echoLength);
        apdu.sendBytesLong(echo, (short) 0, echoLength);
        ISOException.throwIt((short) (ISO7816.SW_BYTES_REMAINING_00 | 0x07));
    }

    private void maximumData(APDU apdu) {
        short   maxData = APDU.getOutBlockSize();
        byte[]  buffer  = apdu.getBuffer();
        Util.arrayFillNonAtomic(buffer, (short) 0, maxData, (byte) 0);
        apdu.setOutgoingAndSend((short) 0, maxData);
    }
    
    private void listObjects(APDU apdu) {
        byte buffer[] = apdu.getBuffer();
        
        if (buffer[ISO7816.OFFSET_P2] != 0) {
            ISOException.throwIt((short)0x9C11);
        }
        
        byte expectedBytes = buffer[ISO7816.OFFSET_LC];
        
        if (expectedBytes < 14) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        
        ISOException.throwIt((short)0x9C12);
    } 
    */ 
}
