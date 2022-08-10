package com.eidna;

import javacard.framework.JCSystem;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.Util;

import javacard.security.RandomData;
import javacard.security.SecretKey;
import javacard.security.KeyBuilder;
import javacard.security.Key;
import javacard.security.KeyPair;
import javacard.security.PublicKey;
import javacard.security.AESKey;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;

import javacard.framework.OwnerPIN;
import javacard.security.Signature;
import javacard.security.KeyAgreement;
import javacardx.crypto.Cipher;


public class Crypto {
    public static final byte minPinSize               = 4;
    public static final byte maxPinSize               = 8;
    public static final byte pinTryLimit              = 3;
    public static final byte authNonceLen             = 15;
    public static final short shortZero               = (short) 0;

    private OwnerPIN        pin;
    private Signature       sigSign, sigVerify;
    private KeyPair         keyPairSession, keyPairVoting, keyPairSigning;
    private ECPublicKey     clientKey, adminKey;
    private AESKey          sessionKey;
    //private DESKey          sessionKey;

    protected Crypto() {
        pin = new OwnerPIN(pinTryLimit, maxPinSize);
        byte[] p = {1, 2, 3, 4, 5}; // TODO: Require PIN change on first session 
        setPin(p, shortZero, (byte) p.length);
        generateAllKeys();
    }

    /*************/
    /* Utilities */
    /*************/
    public boolean RequireSession()
    {
        if (RequirePin() && sessionKey.isInitialized()) {
           return true;
        }
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return false;
    }

    public boolean RequirePin()
    {
        if (pinIsValidated()) {
            return true;
        }
        ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        return false;
    }

    /***********/
    /* Signing */
    /***********/
    public short sign(byte[] buffer, short offset, short length) {
        byte[] orig = JCSystem.makeTransientByteArray((short) 256, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        Util.arrayCopyNonAtomic(buffer, offset, orig, shortZero, length);
        Signature sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
        sig.init(keyPairSigning.getPrivate(), Signature.MODE_SIGN);
        return sig.sign(orig, shortZero, length, buffer, shortZero);
    }

    public boolean verify() {
        Signature sig = Signature.getInstance(Signature.ALG_ECDSA_SHA_512, false);
        return false;
    }

    private short doCipher(byte algorithm, byte direction, Key key, byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
        // https://docs.oracle.com/javacard/3.0.5/api/javacardx/crypto/Cipher.html#init(javacard.security.Key,%20byte,%20byte[],%20short,%20short)
        Cipher cipher   = Cipher.getInstance(algorithm, false);
        cipher.init(key, direction);
        return cipher.doFinal(inBuff, inOffset, inLength, outBuff, outOffset);
    }

    /**************************/
    /* Session Key Management */
    /**************************/
    public short sessionGenerateSecret(byte[] outBuff) {
        byte[] publicData = new byte[clientKey.getSize()];
        short sz = clientKey.getW(publicData, shortZero);

        byte[] secret = new byte[KeyBuilder.LENGTH_AES_256];

        KeyAgreement ag = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH, false);
        ag.init(keyPairSession.getPrivate());
        sz = ag.generateSecret(publicData, shortZero, sz, secret, shortZero);


        return shortZero;
    }



    /***********************/
    /* Key Pair Management */
    /***********************/
    public void deserializeClientKey(byte[] buffer, short offset, short len) {
        clientKey = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_521, false);
        deserializeKey(clientKey, buffer, offset);
    }

    public void deserializeAdminKey(byte[] buffer, short offset, short len) {
        deserializeKey(adminKey, buffer, offset);
    }


    public short serializeSigningKey(byte[] buffer, short offset) {
        return serializeKey((ECPublicKey) keyPairSigning.getPublic(), buffer, offset);
    }

    public short serializeVotingKey(byte[] buffer, short offset) {
        return serializeKey((ECPublicKey) keyPairVoting.getPublic(), buffer, offset);
    }

    private void generateAllKeys() {
        generateKeyPairSession();
        generateKeyPairSigning();
        generateKeyPairVoting();
    }

    private void generateKeyPairSession() {
        keyPairSession = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_521);
        keyPairSession.genKeyPair();
    }

    private void generateKeyPairSigning() {
        keyPairSigning = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_521);
        keyPairSigning.genKeyPair();
    }

    private void generateKeyPairVoting() {
        // NOTE: default public exponent for RSA is 65537 (0x10001)
        // https://docs.oracle.com/javacard/3.0.5/api/javacard/security/KeyPair.html#genKeyPair()
        keyPairVoting = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_521);
        keyPairVoting.genKeyPair();
    }

    private short serializeKey(ECPublicKey key, byte[] buffer, short offset) {
        short l = key.getW(buffer, (short) (offset + Short.BYTES));
        Util.setShort(buffer, offset, l);
        return (short) (l + Short.BYTES);
    }

    private short deserializeKey(ECPublicKey key, byte[] buffer, short offset) {
        return shortZero;
    }
    

    /******************/
    /* PIN Management */
    /******************/
    public boolean checkPin(byte[] buffer, short offset, byte length) {
        return pin.check(buffer, offset, length);
    }

    public byte getPinTriesRemaining() {
        return pin.getTriesRemaining();
    }

    public boolean pinIsValidated() {
        return pin.isValidated();
    }

    public void setPin(byte[] p, short offset, byte len) {
        if (minPinSize <= len && len <= maxPinSize) {
            pin.update(p, shortZero, len);
            pin.resetAndUnblock(); // TODO make this possible only by the issuing authority
        }
    }
}
