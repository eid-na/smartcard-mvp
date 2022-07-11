package com.eidna;

import com.eidna.App;

import java.util.Arrays;
import java.util.Enumeration;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.TestInstance;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.security.Provider;
import java.security.Security;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;

import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.security.NoSuchAlgorithmException;
import javax.crypto.NoSuchPaddingException;

import javacard.framework.Util;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import com.licel.jcardsim.utils.AIDUtil;
import apdu4j.ISO7816;
import com.licel.jcardsim.smartcardio.CardSimulator;

public class AppTest {
    
    private final byte enterPinIns              = 1;
    private final byte challengeRequestIns      = 2;
    private final byte challengeResponseIns     = 3;
    private final byte getVersionIns            = 4;
    private final byte sendPublicKeyIns         = 5;
    private final byte receivePublicKeyIns      = 6;
    private final byte returnDecryptedNonce     = 7;
    private final byte sendEncryptedNonce       = 8;

    private CardSimulator   simulator;
    private CommandAPDU     command;
    private ResponseAPDU    response;
    private KeyPair         keyPair;
    private PublicKey       cardKey;

    public AppTest() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        // Create and install the applet
        simulator       = new CardSimulator();
        AID appletAID   = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, App.class);
        simulator.selectApplet(appletAID);

        // Generate own KeyPair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        keyPair = keyGen.genKeyPair();

        // Generate session key
        

        
    }

    @AfterEach
    void printResponseAPDU() {
        String s = new String(response.getData(), StandardCharsets.UTF_8);
        System.out.println(s);
    }

    @Test
    void testGetVersionIns() {
        command         = new CommandAPDU(0, getVersionIns, 0, 0);
        response        = simulator.transmitCommand(command);
        byte[] version  = {'I', '2', 'P', '_', 'M', 'V', 'P'};
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());
        assertArrayEquals(version, response.getData());    
    }

    @Test
    void testSendPublicKeyIns() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        System.out.println("Getting card's public key");
        command     = new CommandAPDU(0, sendPublicKeyIns, 0, 0);
        response    = simulator.transmitCommand(command);
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());
        cardKey     = deserializeKey(response.getData(), (short) 0);
    }

    @Test
    void testReceivePublicKeyIns() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        System.out.println("Sending public key to the card");
        command = new CommandAPDU(0, receivePublicKeyIns, 0, 0, keyPair.getPublic().getEncoded(), 0, keyPair.getPublic().)
    }

    @Test // TODO: under development
    void authenticateCard() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        System.out.println("Authenticating the card");
        SecureRandom rng    = new SecureRandom();
        byte[] nonce        = new byte[128];
        rng.nextBytes(nonce);
        
        Cipher cipher       = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, cardKey);
        byte[] buffer       = new byte[128];
        cipher.doFinal(buffer, (short) 0, (short) 128, nonce, (short) 0);
       
        command             = new CommandAPDU(0, returnDecryptedNonce, 0, 0, buffer, 0, 128);
        response            = simulator.transmitCommand(command);
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());     // Status OK
        assertArrayEquals(nonce, response.getData());

        // Generate session key
        //AESKey sessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, true);

        //Cipher asymCipher;
        //asymCipher.init(cardKey, Cipher.MODE_ENCRYPT);
        
    }

    @Test
    void sendSessionKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        
    }

    private final PublicKey deserializeKey(byte[] buffer, short offset) throws NoSuchAlgorithmException, InvalidKeySpecException {
        short expLen            = Util.getShort(buffer, offset);
        byte[] slice            = Arrays.copyOfRange(buffer, offset + Short.BYTES, offset + Short.BYTES + expLen);
        BigInteger exp          = new BigInteger(1, slice);

        short modLen            = Util.getShort(buffer, (short) (offset + Short.BYTES + expLen));
        slice                   = Arrays.copyOfRange(buffer, offset + Short.BYTES + expLen, offset + Short.BYTES + expLen + modLen);
        BigInteger mod          = new BigInteger(1, slice);

        RSAPublicKeySpec spec   = new RSAPublicKeySpec(mod, exp);
        KeyFactory keyFactory   = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    private final byte[] serializeKey(PublicKey key, short offset) {
        byte[] buffer;
        if ("RSA" == key.getAlgorithm()) {
            RSAPublicKey k = (RSAPublicKey) key;
            BigInteger exp = k.getPublicExponent();
            BigInteger mod = k.getModulus();
          //  key.get
        }
        return buffer;
    }
}
