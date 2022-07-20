package com.eidna;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import java.security.interfaces.RSAKey;

//import org.bouncycastle.crypto.util.CipherFactory;

import com.licel.jcardsim.smartcardio.JCSCard;

import javacard.framework.JCSystem;
import javacard.framework.APDU;

import javacard.framework.OwnerPIN;

import javacard.security.RandomData;
import javacard.security.KeyBuilder;
import javacard.security.Key;
import javacard.security.KeyPair;
import javacard.security.PublicKey;
import javacard.security.RSAPublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.AESKey;
import javacard.security.ECPublicKey;
import javacardx.crypto.Cipher;


public class App extends Applet implements ISO7816 {
    private short canary                         = (short) 0x6969;
    private final byte maxPinSize               = 8;
    private final byte pinTryLimit              = 3;
    private final byte deselectMagic            = (byte) 0x9696;
    private final byte version[]                = {'I', '2', 'P', '_', 'M', 'V', 'P'};
    private final byte authNonceLen             = (byte) 15;
    private final short shortZero               = (short) 0;

    private final byte getVersionIns            = 4;
    private final byte sendPublicKeyIns         = 5;
    private final byte receivePublicKeyIns      = 6;
    private final byte returnDecryptedNonceIns     = 7;
    private final byte sendEncryptedNonceIns       = 8;
    private final byte receiveSessionKeyIns     = 9;
    private final byte receiveDecryptedNonceIns = 10;
    private final byte getPinTriesRemainingIns  = 11;
    private final byte tryPinIns                = 12;

    private byte[] initParamsBytes;
    private OwnerPIN pin;
    private byte[] expectedNonce;
    private KeyPair keyPair;
    private RSAPublicKey clientKey;
    private AESKey sessionKey;

    private byte[] deselectFlag;
    
    protected App(byte[] bArray, short bOffset, byte bLength) {
        if (bLength > 0) {
            byte iLen       = bArray[bOffset]; // aid length
            
            bOffset         = (short) (bOffset + iLen + 1);
            byte cLen       = bArray[bOffset]; // info length
            
            bOffset         = (short) (bOffset + 3);
            byte aLen       = bArray[bOffset]; // applet data length
            
            initParamsBytes = new byte[aLen];
            Util.arrayCopyNonAtomic(bArray, (short) (bOffset + 1), initParamsBytes, shortZero, aLen);
        }

        // Create the PIN
        if (pin == null) {
            pin = new OwnerPIN(pinTryLimit, maxPinSize);
            byte[] p = {1, 2, 3, 4, 5};
            pin.update(p, shortZero, (byte) 5);
            pin.resetAndUnblock();
        }

        DoReset();
        handleGenerateKeyPair();

        register();
    }    

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new App(bArray, bOffset,bLength);
    }

    public void process(APDU apdu) {
        if(selectingApplet())
            return;

       // ConditionalReset();
        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS])
        {
            case receivePublicKeyIns:
                handleReceivePublicKey(apdu);
                break;
            case sendPublicKeyIns:
                handleSendPublicKey(apdu);
                break;
            case getVersionIns:
                handleGetVersion(apdu);
                break;
            case returnDecryptedNonceIns:
                handleReturnDecryptedNonce(apdu);
                break;
            case sendEncryptedNonceIns:
                handleSendEncryptedNonce(apdu);
                break;
            case receiveSessionKeyIns:
                handleReceiveSessionKey(apdu);
                break;
            case receiveDecryptedNonceIns:
                handleReceiveDecryptedNonce(apdu);
                break;
            case getPinTriesRemainingIns:
                handleGetPinTriesRemaining(apdu);
                break;
            case tryPinIns:
                handleTryPin(apdu);
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
    private void ConditionalReset()
    {
        if (CheckReset())
            DoReset();
    }
    */
    private void DoReset()
    {
    //    Pin.setValidatedFlag(false);
    //    deselectFlag[0] = deselectMagic;
    }

    private boolean RequirePin(APDU apdu)
    {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        } else {
            return true;
        }
        return false;
    }

    private void RequireSession(APDU apdu)
    {
        if (!RequirePin(apdu)) {
            return;
        }
    //    if (!Pin.isValidated())
    //        ISOExcepion.throwIt(ISO7816.SECURITY_STATUS_NOT_SATISFIED);
    }

    private void handleGenerateKeyPair() {
        keyPair         = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        //byte[] exp      = new byte[3];
        //secureRandom(exp, shortZero, (short) 3);
        //RSAPublicKey pk = (RSAPublicKey) keyPair.getPublic();
        //pk.setExponent(exp, shortZero, (short) 3);
        keyPair.genKeyPair();
    }

    private void handleGetVersion(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(version, shortZero, buffer, shortZero, (short) version.length);
        apdu.setOutgoingAndSend(shortZero, (short) version.length);
    }

    private void handleGetPinTriesRemaining(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        buffer[0] = pin.getTriesRemaining();
        apdu.setOutgoingAndSend(shortZero, (short) 1);
    }

    private void handleTryPin(APDU apdu) {
        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();
        if (!pin.check(buffer, (short) ISO7816.OFFSET_CDATA, (byte) apdu.getIncomingLength())) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void handleSendPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();    
        short sz = serializeKey((RSAPublicKey) keyPair.getPublic(), buffer, shortZero);
        apdu.setOutgoingAndSend(shortZero,  sz);
    }

    private void handleReceivePublicKey(APDU apdu) {
        apdu.setIncomingAndReceive();
        
        //if (apdu.getIncomingLength() != 136) { // 1024 bit RSA key: 128 byte modulus, 3 byte exponent, 2 shorts to describe lengths, and 1 of ???
        //    apdu.setOutgoing();
        //    ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        //} else {
            byte[] buffer   = apdu.getBuffer();
            clientKey       = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);   
            deserializeKey(clientKey, buffer, ISO7816.OFFSET_CDATA);
        //}
    }

    private void handleReturnDecryptedNonce(APDU apdu) {
        if (!RequirePin(apdu)) {
            return;
        }
        apdu.setIncomingAndReceive();
       

        byte[] buffer = new byte[256];
        //short len = doCipher(Cipher.ALG_RSA_PKCS1, Cipher.MODE_ENCRYPT, clientKey, version, shortZero, (short) version.length, buffer, shortZero);
       // len = doCipher(Cipher.ALG_RSA_NOPAD, Cipher.MODE_DECRYPT, keyPair.getPrivate(), buffer, shortZero, len, apdu.getBuffer(), shortZero);
        short len = doCipher(Cipher.ALG_RSA_PKCS1, Cipher.MODE_DECRYPT, keyPair.getPrivate(), apdu.getBuffer(), ISO7816.OFFSET_CDATA, apdu.getIncomingLength(), buffer, shortZero);
        Util.arrayCopyNonAtomic(buffer, shortZero, apdu.getBuffer(), shortZero, len);
        apdu.setOutgoingAndSend(shortZero, len);
        // byte[] buffer = apdu.getBuffer();
        //byte[] nonce  = new byte[2 * apdu.getIncomingLength()]; // Expect 127 are needed, but allocate extra
    
        //short len = doCipher(Cipher.ALG_RSA_PKCS1, Cipher.MODE_DECRYPT, keyPair.getPrivate(), buffer, ISO7816.OFFSET_CDATA, apdu.getIncomingLength(), nonce, shortZero);
        //Util.arrayCopyNonAtomic(nonce, shortZero, buffer, shortZero, len);
        //apdu.setOutgoingAndSend(shortZero, len);
    }

    private void handleSendEncryptedNonce(APDU apdu) {
        if (!RequirePin(apdu)) {
            return;
        }

        expectedNonce = JCSystem.makeTransientByteArray(authNonceLen, JCSystem.CLEAR_ON_DESELECT);
        secureRandom(expectedNonce, shortZero, (short) expectedNonce.length);
        short len = doCipher(
            Cipher.ALG_RSA_PKCS1, 
            Cipher.MODE_ENCRYPT, 
            clientKey, 
            expectedNonce, 
            shortZero, 
            (short) expectedNonce.length, 
            apdu.getBuffer(), 
            shortZero
        );
        apdu.setOutgoingAndSend(shortZero, len);
    }

    private void handleReceiveDecryptedNonce(APDU apdu) {
        if (!RequirePin(apdu)) {
            return;
        }
        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();
        if ((short) expectedNonce.length != apdu.getIncomingLength()
            ||  0 != Util.arrayCompare(expectedNonce, shortZero, buffer, ISO7816.OFFSET_CDATA, (short) expectedNonce.length)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void handleReceiveSessionKey(APDU apdu) {
        if (!RequirePin(apdu)) {
            return;
        }

        byte[] buffer = new byte[32]; // 32 bytes in a 256-bit key
        doCipher(
            Cipher.ALG_RSA_PKCS1, 
            Cipher.MODE_DECRYPT, 
            keyPair.getPrivate(), 
            apdu.getBuffer(), shortZero, apdu.getIncomingLength(), 
            buffer, shortZero
        );
        sessionKey.setKey(buffer, (short) buffer.length);
    }

    private short serializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        // https://stackoverflow.com/questions/42690733/javacard-send-rsa-public-key-in-apdu
 //       RSAPublicKey key = (RSAPublicKey) keyPair.getPublic();
        
        short expLen    = key.getExponent(buffer, (short) (offset + Short.BYTES));
        Util.setShort(buffer, offset, expLen);
        
        short modLen    = key.getModulus(buffer, (short) (offset + Short.BYTES + expLen + Short.BYTES));
        Util.setShort(buffer, (short) (offset + Short.BYTES + expLen), modLen);

        return (short) (expLen + Short.BYTES + modLen + Short.BYTES);
    }

    private final short deserializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        short expLen = Util.getShort(buffer, offset);
        key.setExponent(buffer, (short) (offset + Short.BYTES), expLen);
        
        short modLen = Util.getShort(buffer, (short) (offset + Short.BYTES + expLen));
        key.setModulus(buffer, (short) (offset + Short.BYTES + expLen + Short.BYTES), modLen);

        /*
        short off       = ISO7816.OFFSET_CDATA;
            short expLen    = Util.getShort(buffer, off);       off += Short.BYTES;
            clientKey.setExponent(buffer, shortZero, expLen);   off += expLen;
            short modLen    = Util.getShort(buffer, off);       off += Short.BYTES;
            clientKey.setModulus(buffer, off, modLen);
        */
        return (short) (expLen + Short.BYTES + modLen + Short.BYTES);
    }

    private short doCipher(byte algorithm, byte direction, Key key, byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
        Cipher cipher  = Cipher.getInstance(algorithm, false);
        cipher.init(key, direction);
        return cipher.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
    }

    private void secureRandom(byte[] out, short offset, short length) {
        RandomData rng  = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        rng.generateData(out, offset, length);
    }

    /*
    private byte[] receiveCopy(APDU apdu) {
        short bts_read = apdu.setIncomingAndReceive();
        byte[] buffer = byte[apdu.getIncomingLength()];
        Util.arrayCopyNonAtomic(apdu.getBuffer(), ISO7816.OFFSET_CDATA, buffer, shortZero, bts_read);
        short bts = 0;
        while (0 < (bts = apdu.receiveBytes(shortZero))) {
            Util.arrayCopyNonAtomic(apdu.getBuffer(), shortZero, buffer, bts_read, bts);
            bts_read += bts;
        }
        return buffer;
    }*/

    
}
