package com.eidna;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.framework.APDU;

import javacard.security.RandomData;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.PublicKey;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import javacard.security.RSAPrivateKey;
import javacard.security.ECPublicKey;

public class App extends Applet implements ISO7816 {
    private byte canary                         = (byte) 0x6969;
    private final byte maxPinSize               = 8;
    private final byte pinTryLimit              = 3;
    private final byte deselectMagic            = (byte) 0x9696;
    private final byte version[]                = {'I', '2', 'P', '_', 'M', 'V', 'P'};
    private final byte authNonceLen             = (byte) 4096;
    private final short shortZero               = (short) 0;

    private final byte enterPinIns              = 1;
    private final byte challengeRequestIns      = 2;
    private final byte challengeResponseIns     = 3;
    private final byte getVersionIns            = 4;
    private final byte sendPublicKeyIns         = 5;
    private final byte receivePublicKeyIns      = 6;
    private final byte returnDecryptedNonce     = 7;
    private final byte sendEncryptedNonce       = 8;

    private byte[] initParamsBytes;
    //private OwnerPin Pin;
    private KeyPair keyPair;
    private RSAPublicKey clientKey;

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

      //  transientMemory = JCSystem.makeTransientByteArray(LENGTH_ECHO_BYTES, JCSystem.CLEAR_ON_RESET);
       // Pin             = new OwnerPIN(pinTryLimit, maxPinSize);
      //  deselectFlag    = JCSystem.makeTransientByteArray(1, JCSystem.CLEAR_ON_DESELECT);
      //  DoReset();

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
        //    case enterPinIns:
        //        EnterPin(apdu);
        //        break;
            case receivePublicKeyIns:
                handleReceivePublicKey(apdu);
                break;
            case sendPublicKeyIns:
                handleSendPublicKey(apdu);
                break;
            case getVersionIns:
                handleGetVersion(apdu);
                break;
            case returnDecryptedNonce:
                handleReturnDecryptedNonce(apdu);
                break;
            case sendEncryptedNonce:
                handleSendEncryptedNonce(apdu);
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

    private void handleGenerateKeyPair() {
        keyPair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
    }

    private void handleGetVersion(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(version, shortZero, buffer, shortZero, (short) version.length);
        apdu.setOutgoingAndSend(shortZero, (short) version.length);
    }

    private void handleSendPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();    
        keyPair.getPublic();
        short sz = serializeKey(buffer, shortZero);
        apdu.setOutgoingAndSend(shortZero,  sz);
    }

    private void handleReceivePublicKey(APDU apdu) {
        deserializeKey(clientKey, apdu.getBuffer(), shortZero);
        apdu.setOutgoingAndSend(shortZero, shortZero);
    }

    private void handleReturnDecryptedNonce(APDU apdu) {
        Cipher.OneShot cipher = Cipher.OneShot.open(Cipher.CIPHER_RSA, Cipher.PAD_PKCS1);
        cipher.init(keyPair.getPrivate(), Cipher.MODE_DECRYPT);

        byte[] buffer = apdu.getBuffer();
        byte[] nonce = new byte[authNonceLen];
        cipher.doFinal(buffer, shortZero, apdu.getIncomingLength(), nonce, shortZero);
        Util.arrayCopyNonAtomic(nonce, shortZero, buffer, shortZero, authNonceLen);
    }

    private void handleSendEncryptedNonce(APDU apdu) {
        RandomData.OneShot rng = RandomData.OneShot.open(RandomData.ALG_SECURE_RANDOM);
        byte[] nonce = new byte[authNonceLen];
        rng.nextBytes(nonce, shortZero, (short) nonce.length);
        
        Cipher.OneShot cipher = Cipher.OneShot.open(Cipher.CIPHER_RSA, Cipher.PAD_PKCS1);
        cipher.init(keyPair.getPrivate(), Cipher.MODE_ENCRYPT);

        byte[] ciphertext = new byte[authNonceLen];
        cipher.doFinal(nonce, shortZero, nonce.length, ciphertext, shortZero);
        
        Util.arrayCopyNonAtomic(ciphertext, shortZero, apdu.getBuffer(), shortZero, (short) ciphertext.length);
    }

    private short serializeKey(byte[] buffer, short offset) {
        // https://stackoverflow.com/questions/42690733/javacard-send-rsa-public-key-in-apdu
        RSAPublicKey key = (RSAPublicKey) keyPair.getPublic();
        
        short expLen    = key.getExponent(buffer, (short) (offset + Short.BYTES));
        Util.setShort(buffer, offset, expLen);
        
        short modLen    = key.getModulus(buffer, (short) (offset + Short.BYTES + expLen));
        Util.setShort(buffer, (short) (offset + Short.BYTES + expLen), modLen);

        return (short) (expLen + Short.BYTES + modLen + Short.BYTES);
    }

    private final short deserializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        short expLen = Util.getShort(buffer, offset);
        key.setExponent(buffer, (short) (offset + Short.BYTES), expLen);
        
        short modLen = Util.getShort(buffer, (short) (offset + Short.BYTES + expLen));
        key.setModulus(buffer, (short) (offset + Short.BYTES + expLen + Short.BYTES), modLen);
        
        return (short) (expLen + Short.BYTES + modLen + Short.BYTES);
    }
}
