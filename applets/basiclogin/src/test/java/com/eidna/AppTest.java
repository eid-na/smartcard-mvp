package com.eidna;

import java.nio.charset.StandardCharsets;

import org.bouncycastle.jcajce.provider.symmetric.AES.KeyGen;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeFalse;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import com.eidna.App;

import java.security.SecureRandom;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import javacardx.crypto.Cipher;

import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.framework.AID;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
//import javacard.security.KeyBuilder;
//import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
//import javacard.security.AESKey;
//import javacard.security.Signature;

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

    @Test
    void basicLogin() {
        // 1. Create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. Install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, App.class);

        // 3. Select applet
        simulator.selectApplet(appletAID);

        // Get version
        CommandAPDU commandAPDU = new CommandAPDU(0, 4, 0, 0);
        ResponseAPDU response = simulator.transmitCommand(commandAPDU);
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());             // Status OK
        byte[] version                = {'I', '2', 'P', '_', 'M', 'V', 'P'};
        assertArrayEquals(version, response.getData());     // Result

        // Get public key
        System.out.println("Getting card's public key");
        commandAPDU     = new CommandAPDU(0, sendPublicKeyIns, 0, 0);
        response       = simulator.transmitCommand(commandAPDU);
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());     // Status OK
        String v                    = new String(response.getData(), StandardCharsets.UTF_8);
        System.out.println(v);
        
        RSAPublicKey cardKey        = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, true);
        deserializeKey(cardKey, response.getData(), (short) 0);

        // Generate own KeyPair
    //    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
 //       keyGen.initialize(KeyBuilder.LENGTH_RSA_1024);
  //      KeyPair keyPair = keyGen.genKeyPair();
        
        // Authenticate card
        System.out.println("Authenticating the card");
        SecureRandom rng    = new SecureRandom();
        byte[] nonce        = new byte[4096];
        rng.nextBytes(nonce);
        
       /*
        Cipher cipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        cipher.init(cardKey, Cipher.MODE_ENCRYPT);
        byte[] buffer = new byte[4096];
        cipher.doFinal(buffer, (short) 0, (short) 4096, nonce, (short) 0);
        v                    = new String(nonce, StandardCharsets.UTF_8);
        System.out.println(v);
        v                    = new String(buffer, StandardCharsets.UTF_8);
        System.out.println(v);
        */ /*
        commandAPDU         = new CommandAPDU(0, returnDecryptedNonce, 0, 0, buffer, 0, 4096);
        response            = simulator.transmitCommand(commandAPDU);
        assertEquals(ISO7816.SW_NO_ERROR, response.getSW());     // Status OK
        */
        //assertArrayEquals(nonce, response.getData());

        // Generate session key
        //AESKey sessionKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, true);

        //Cipher asymCipher;
        //asymCipher.init(cardKey, Cipher.MODE_ENCRYPT);

        
    }

    private final short deserializeKey(RSAPublicKey key, byte[] buffer, short offset) {
        short expLen = Util.getShort(buffer, offset);
        key.setExponent(buffer, (short) (offset + Short.BYTES), expLen);
        
        short modLen = Util.getShort(buffer, (short) (offset + Short.BYTES + expLen));
        key.setModulus(buffer, (short) (offset + Short.BYTES + expLen + Short.BYTES), modLen);
        
        return (short) (expLen + Short.BYTES + modLen + Short.BYTES);
    }
}
