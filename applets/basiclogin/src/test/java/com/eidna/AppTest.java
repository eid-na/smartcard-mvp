package com.eidna;

import com.eidna.App;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;
import java.util.Arrays;
import java.util.Enumeration;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.TestInstance;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import java.security.Provider;
import java.security.Security;
import java.security.Key;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;

import java.security.spec.RSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;

import javax.crypto.NoSuchPaddingException;

import javacard.framework.Util;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.swing.text.StyledEditorKit;

import com.licel.jcardsim.utils.AIDUtil;
import apdu4j.ISO7816;
import com.licel.jcardsim.smartcardio.CardSimulator;

public class AppTest {
    
    private static final byte maxPinSize               = 8;
    private static final byte pinTryLimit              = 3;

    private static final byte getVersionIns            = 4;
    private static final byte sendPublicKeyIns         = 5;
    private static final byte receivePublicKeyIns      = 6;
    private static final byte returnDecryptedNonceIns  = 7;
    private static final byte sendEncryptedNonceIns    = 8;
    //private static final byte receiveSessionKeyIns     = 9;
    private static final byte receiveDecryptedNonceIns = 10;
    private static final byte getPinTriesRemainingIns  = 11;
    private static final byte tryPinIns                = 12;
    private static final byte sendSessionKeyIns        = 13;
    private static final byte testSessionKeyIns        = 14;

    private static final int   asymKeyLen              = 1024;
    //private static final int   sessKeyLen              = 256;
    private static final int   authNonceLen            = 15;
    private static final short shortZero               = (short) 0;

    private static final byte[] expectedVersion        = {'I', '2', 'P', '_', 'M', 'V', 'P'};
    //private static final byte[] IV                     = {3, 5, 7, 11, 13, 5, 7, 13, 11, 5, 3, 7, 13, 11, 7, 5};
    private static final byte[] IV       = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    private CommandAPDU             command;
    private ResponseAPDU            response;
    private static CommandAPDU      cmd;
    private static ResponseAPDU     rsp;
    private static CardSimulator    simulator;
    private static KeyPair          keyPair;
    private static PublicKey        cardKey;
    private static SecretKey        sessionKey;

    @BeforeAll
    public static void setup() throws 
        NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException,
        InvalidKeyException, IllegalBlockSizeException, BadPaddingException,
        InvalidAlgorithmParameterException {      
        
        Security.addProvider(new BouncyCastleProvider());

        // Create and install the applet
        simulator       = new CardSimulator();
        AID appletAID   = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, App.class);
        simulator.selectApplet(appletAID);

        // Generate own KeyPair
        System.out.println("Generating test harness' assymetric key");
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(asymKeyLen);
        keyPair = keyPairGen.genKeyPair();
        //String s = new String(keyPair.getPublic().getEncoded(), StandardCharsets.UTF_8);
        //System.out.println(s);

        /*************/
        /* PIN TESTS */
        /*************/

        // Check number of PIN tries remaining
        cmd         = new CommandAPDU(0, getPinTriesRemainingIns, 0, 0);
        rsp         = simulator.transmitCommand(cmd);
        byte[] buffer = rsp.getData();
        assertEquals(pinTryLimit, buffer[0]);

        // Try an incorrect pin
        byte[] pin  = {1, 2, 3, 4, 5, 6};
        cmd         = new CommandAPDU(0, tryPinIns, 0, 0, pin);
        rsp         = simulator.transmitCommand(cmd);
        assertEquals(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED, rsp.getSW());

        // Check number of PIN tries remaining
        cmd         = new CommandAPDU(0, getPinTriesRemainingIns, 0, 0);
        rsp         = simulator.transmitCommand(cmd);
        buffer = rsp.getData();
        //System.out.print(buffer[0]);
        assertEquals(pinTryLimit-1, buffer[0]);
        
        // Try the correct pin
        pin         = new byte[] {1, 2, 3, 4, 5};
        cmd         = new CommandAPDU(0, tryPinIns, 0, 0, pin);
        rsp         = simulator.transmitCommand(cmd);
        assertEquals(ISO7816.SW_NO_ERROR, rsp.getSW());

        // Check number of PIN tries remaining
        cmd         = new CommandAPDU(0, getPinTriesRemainingIns, 0, 0);
        rsp         = simulator.transmitCommand(cmd);
        buffer = rsp.getData();
        //System.out.print(buffer[0]);
        assertEquals(pinTryLimit, buffer[0]);

        /************************/
        /* Exchange public keys */
        /************************/

        // Send to card
        System.out.println("Sending public key to the card");
        buffer = serializeKey(keyPair.getPublic(), (short) 0);
        cmd    = new CommandAPDU(0, receivePublicKeyIns, 0, 0, buffer);
        rsp    = simulator.transmitCommand(cmd);
        assertEquals(ISO7816.SW_NO_ERROR, rsp.getSW());

        // Receive from card
        cmd    = new CommandAPDU(0, sendPublicKeyIns, 0, 0);
        rsp    = simulator.transmitCommand(cmd);
        assertEquals(ISO7816.SW_NO_ERROR, rsp.getSW());
        cardKey = deserializeRSAPublicKey(rsp.getData(), (short) 0);

        /**************/
        /* Challenges */
        /**************/

        // Receive challenge
        cmd     = new CommandAPDU(0, sendEncryptedNonceIns, 0, 0);        
        rsp     = simulator.transmitCommand(cmd);
        assertEquals(ISO7816.SW_NO_ERROR, rsp.getSW());     // Status OK
        buffer  = doCipher("RSA/ECB/PKCS1Padding", Cipher.DECRYPT_MODE, keyPair.getPrivate(), rsp.getData());
        cmd     = new CommandAPDU(0, receiveDecryptedNonceIns, 0, 0, buffer);
        rsp     = simulator.transmitCommand(cmd);
        assertEquals(ISO7816.SW_NO_ERROR, rsp.getSW());

        // Send challenge
        SecureRandom rng    = new SecureRandom();
        byte[] nonce        = new byte[authNonceLen];
        rng.nextBytes(nonce);
        buffer              = doCipher("RSA/ECB/PKCS1Padding", Cipher.ENCRYPT_MODE, cardKey, nonce);        
        cmd                 = new CommandAPDU(0, returnDecryptedNonceIns, 0, 0, buffer);        
        rsp                 = simulator.transmitCommand(cmd);
        assertEquals(ISO7816.SW_NO_ERROR, rsp.getSW());
        assertArrayEquals(nonce, rsp.getData());

        /*********************/
        /* Establish session */
        /*********************/

        // Receive session key
        cmd             = new CommandAPDU(0, sendSessionKeyIns, 0, 0);
        rsp             = simulator.transmitCommand(cmd);
        assertEquals(ISO7816.SW_NO_ERROR, rsp.getSW());
        byte[] scratch  = doCipher("RSA/ECB/PKCS1Padding", Cipher.DECRYPT_MODE, keyPair.getPrivate(), rsp.getData());
        sessionKey      = deserializeSymmKey(scratch, shortZero, "AES");
        System.out.println(Hex.toHexString(sessionKey.getEncoded()));
        System.out.println(sessionKey.getEncoded().length);
    }

    @AfterEach
    void printResponseAPDU() {
        if (null != response && 0 < response.getData().length) {
            String s = new String(response.getData(), StandardCharsets.UTF_8);
            System.out.println(s);
        }
    }

    @Test
    void testGetVersionIns() {
        command         = new CommandAPDU(0, getVersionIns, 0, 0);
        response        = simulator.transmitCommand(command);
//        byte[] version  = {'I', '2', 'P', '_', 'M', 'V', 'P'};
 //       assertEquals(ISO7816.SW_NO_ERROR, response.getSW());
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());
        assertArrayEquals(expectedVersion, response.getData());    
    }

    @Test
    void testSessionKey() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        command         = new CommandAPDU(0, testSessionKeyIns, 0, 0);
        response        = simulator.transmitCommand(command);
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());
        System.out.println(Hex.toHexString(response.getData()));
        byte[] v        = doCipher("AES/CBC/PKCS5Padding", Cipher.DECRYPT_MODE, sessionKey, response.getData());
        assertArrayEquals(expectedVersion, v);
    }

    private static final SecretKey deserializeSymmKey(byte[] buffer, short offset, String alg) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeySpec spec          = new SecretKeySpec(buffer, alg);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(alg);
        return keyFactory.generateSecret(spec);
    }

    private static final PublicKey deserializeRSAPublicKey(byte[] buffer, short offset) throws NoSuchAlgorithmException, InvalidKeySpecException {
        short expLen            = Util.getShort(buffer, offset);                        offset += Short.BYTES;
        byte[] slice            = Arrays.copyOfRange(buffer, offset, offset + expLen);  offset += expLen;
        BigInteger exp          = new BigInteger(1, slice);

        short modLen            = Util.getShort(buffer, offset);                        offset += Short.BYTES;
        slice                   = Arrays.copyOfRange(buffer, offset, offset + modLen);
        BigInteger mod          = new BigInteger(1, slice);

        RSAPublicKeySpec spec   = new RSAPublicKeySpec(mod, exp);
        KeyFactory keyFactory   = KeyFactory.getInstance("RSA");

        return keyFactory.generatePublic(spec);
    }

    private static final byte[] serializeKey(PublicKey key, short offset) {
        if ("RSA" == key.getAlgorithm()) {
            RSAPublicKey k = (RSAPublicKey) key;
            byte[] exp = k.getPublicExponent().toByteArray();
            byte[] mod = k.getModulus().toByteArray();
            short len = (short) (Short.BYTES + exp.length + Short.BYTES + mod.length);
            byte[] buffer = new byte[len];

            short off = 0;
            Util.setShort(buffer, off, (short) exp.length);                                 off += Short.BYTES;
            for (int i=0; i < exp.length; i += 1) {
                buffer[off + i] = exp[i];
            } off += exp.length;

            Util.setShort(buffer, off, (short) mod.length);                                 off += Short.BYTES;
            for (int i=0; i < mod.length; i += 1) {
                buffer[off + i] = mod[i];
            }
            return buffer;
        }
        byte[] buf = new byte[1];
        return buf;
    }

    private static byte[] doCipher(String algorithm, int mode, Key key, byte[] inBuff) 
        throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, 
                IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        // https://docs.oracle.com/javase/8/docs/technotes/guides/security/SunProviders.html
        Cipher cipher = Cipher.getInstance(algorithm);
        //IvParameterSpec iv = new IvParameterSpec(IV);
        cipher.init(mode, key);//, iv);
        return cipher.doFinal(inBuff);
    }
}
