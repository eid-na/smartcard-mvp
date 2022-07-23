package com.eidna;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import java.nio.Buffer;
import java.security.interfaces.RSAKey;

//import org.bouncycastle.crypto.util.CipherFactory;
 

import javacard.framework.JCSystem;
import javacard.framework.APDU;

import javacard.framework.OwnerPIN;

import javacard.security.RandomData;
import javacard.security.SecretKey;
import javacard.security.KeyBuilder;
import javacard.security.Key;
import javacard.security.KeyPair;
import javacard.security.PublicKey;
import javacard.security.RSAPublicKey;
import javacard.security.RSAPrivateKey;
import javacard.security.AESKey;
import javacard.security.DESKey;
import javacard.security.ECPublicKey;
import javacardx.crypto.Cipher;


public class App extends Applet implements ISO7816 {
    private final byte maxPinSize               = 8;
    private final byte pinTryLimit              = 3;
    private final byte version[]                = {'I', '2', 'P', '_', 'M', 'V', 'P'};
    private final byte authNonceLen             = (byte) 15;
    private final short shortZero               = (short) 0;

    private final byte getVersionIns            = 4;
    private final byte sendPublicKeyIns         = 5;
    private final byte receivePublicKeyIns      = 6;
    private final byte returnDecryptedNonceIns  = 7;
    private final byte sendEncryptedNonceIns    = 8;
   // private final byte receiveSessionKeyIns     = 9;
    private final byte receiveDecryptedNonceIns = 10;
    private final byte getPinTriesRemainingIns  = 11;
    private final byte tryPinIns                = 12;
    private final byte sendSessionKeyIns        = 13;
    private final byte testSessionKeyIns        = 14;

    private byte[]          initParamsBytes;
    private OwnerPIN        pin;
    private byte[]          expectedNonce;
    private KeyPair         keyPair, signingKeyPair;
    private RSAPublicKey    clientKey;
    private AESKey          sessionKey;
    //private DESKey          sessionKey;

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

        //DoReset();
        handleSetPin();
        generateSigningKeyPair();
        generateKeyPair();

        register();
    }    

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new App(bArray, bOffset,bLength);
    }

    public void process(APDU apdu) {
        if(selectingApplet())
            return;

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
          //  case receiveSessionKeyIns:
           //     handleReceiveSessionKey(apdu);
           //     break;
            case receiveDecryptedNonceIns:
                handleReceiveDecryptedNonce(apdu);
                break;
            case getPinTriesRemainingIns:
                handleGetPinTriesRemaining(apdu);
                break;
            case tryPinIns:
                handleTryPin(apdu);
                break;
            case sendSessionKeyIns:
                handleSendSessionKey(apdu);
                break;
            case testSessionKeyIns:
                handleTestSessionKey(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void DoReset()
    {
        // ???
    }

    private boolean RequirePin()
    {
        if (pin.isValidated()) {
            return true;
        }
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return false;
    }

    private boolean RequireSession()
    {
        if (RequirePin() && sessionKey.isInitialized()) {
           return true;
        }
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return false;
    }

    private void handleSetPin() {
        pin = new OwnerPIN(pinTryLimit, maxPinSize);
        byte[] p = {1, 2, 3, 4, 5}; // TODO: set via APDU with issuing authority's permissions
        pin.update(p, shortZero, (byte) 5);
        pin.resetAndUnblock();
    }

    private void generateSigningKeyPair() {
        signingKeyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
        signingKeyPair.genKeyPair();
    }

    private void generateKeyPair() {
        // NOTE: default public exponent for RSA is 65537 (0x10001)
        // https://docs.oracle.com/javacard/3.0.5/api/javacard/security/KeyPair.html#genKeyPair()
        keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
    }

    private void handleGenerateSessionKey() {
        sessionKey = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
            KeyBuilder.LENGTH_AES_256, 
            false
        );
        byte[] scratch = new byte[(short) (sessionKey.getSize() / 8)]; // bits -> bytes
        secureRandom(scratch, shortZero, (short) scratch.length);
        sessionKey.setKey(scratch, shortZero);
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
        byte[] buffer   = apdu.getBuffer();
        clientKey       = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);   
        deserializeKey(clientKey, buffer, ISO7816.OFFSET_CDATA);
    }

    private void handleReturnDecryptedNonce(APDU apdu) {
        if (!RequirePin()) {
            return;
        }
        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();
        byte[] scratch = new byte[apdu.getIncomingLength()];
        
        Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, scratch, shortZero, apdu.getIncomingLength()); 
        short len = doCipher(
            Cipher.ALG_RSA_PKCS1, 
            Cipher.MODE_DECRYPT, 
            keyPair.getPrivate(), 
            scratch, 
            shortZero, 
            apdu.getIncomingLength(), 
            buffer, 
            shortZero
        );
        apdu.setOutgoingAndSend(shortZero, len);
    }

    private void handleSendEncryptedNonce(APDU apdu) {
        if (!RequirePin()) {
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
        if (!RequirePin()) {
            return;
        }
        apdu.setIncomingAndReceive();
        byte[] buffer = apdu.getBuffer();
        if ((short) expectedNonce.length != apdu.getIncomingLength()
            ||  0 != Util.arrayCompare(expectedNonce, shortZero, buffer, ISO7816.OFFSET_CDATA, (short) expectedNonce.length)) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void handleSendSessionKey(APDU apdu) {
        if (!RequirePin()) {
            return;
        }
        handleGenerateSessionKey();
        byte[] scratch = new byte[(short) (sessionKey.getSize() / 8)]; // bits -> bytes
        sessionKey.getKey(scratch, shortZero);
        short len = doCipher(
            Cipher.ALG_RSA_PKCS1, 
            Cipher.MODE_ENCRYPT, 
            clientKey, 
            scratch, shortZero, (short) scratch.length, 
            apdu.getBuffer(), shortZero
        );
        apdu.setOutgoingAndSend(shortZero, len);
    }

    private void handleTestSessionKey(APDU apdu) {
        if (!RequireSession()) {
            return;
        }
        //byte[] scratch = new byte[128];
        //Util.arrayCopyNonAtomic(version, shortZero, scratch, shortZero, (short) version.length);
       /* short len = doCipher(
            Cipher.ALG_AES_CBC_PKCS5, 
            Cipher.MODE_ENCRYPT, 
            sessionKey, 
            version, shortZero, (short) version.length, 
            apdu.getBuffer(), shortZero
        );*/

        // TODO: Find a system that supports AES keys and not just DES
      //  Cipher cipher  = Cipher.getInstance(Cipher.ALG_DES_CBC_PKCS5, false);
        //cipher.init(sessionKey, Cipher.MODE_ENCRYPT);
        //short len = cipher.doFinal(version, shortZero, (short) version.length, apdu.getBuffer(), shortZero);
       // apdu.setOutgoingAndSend(shortZero, len);
    }

    private short serializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        // https://stackoverflow.com/questions/42690733/javacard-send-rsa-public-key-in-apdu
 //       RSAPublicKey key = (RSAPublicKey) keyPair.getPublic();
        
        short expLen    = key.getExponent(buffer, (short) (offset + Short.BYTES));
        Util.setShort(buffer, offset, expLen);
        
        offset += Short.BYTES + expLen;
        short modLen    = key.getModulus(buffer, (short) (offset + Short.BYTES));
        Util.setShort(buffer, offset, modLen);

        return (short) (expLen + Short.BYTES + modLen + Short.BYTES);
    }

    private short deserializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        short expLen = Util.getShort(buffer, offset);
        key.setExponent(buffer, (short) (offset + Short.BYTES), expLen);
        
        short modLen = Util.getShort(buffer, (short) (offset + Short.BYTES + expLen));
        key.setModulus(buffer, (short) (offset + Short.BYTES + expLen + Short.BYTES), modLen);

        return (short) (expLen + Short.BYTES + modLen + Short.BYTES);
    }

    private short doCipher(byte algorithm, byte direction, Key key, byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
        // https://docs.oracle.com/javacard/3.0.5/api/javacardx/crypto/Cipher.html#init(javacard.security.Key,%20byte,%20byte[],%20short,%20short)
        Cipher cipher   = Cipher.getInstance(algorithm, false);
       // byte[] IV       = {3, 5, 7, 11, 13, 5, 7, 13, 11, 5, 3, 7, 13, 11, 7, 5};
        byte[] IV       = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
       // cipher.init(key, direction, IV, shortZero, (short) IV.length);
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
