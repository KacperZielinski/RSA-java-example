package pki;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;


public class DigitalSignatureTest {

    private KeyPair senderKeyPair;

    @BeforeEach
    public void setup() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        senderKeyPair = keyPairGenerator.generateKeyPair();
    }

    /**
     * sender creates:
     *  public/private key pair: ("pub512", "priv12"),
     *  message: "signedMessage"
     *  digital signature: "12jk4hkh12" <- encrypted with PRIVATE key enc("signedMessage", "priv12")
     *
     * receiver gets:
     *  public key of sender: "pub512"
     *  message: "signedMessage"
     *  digital signature: "12jk4hkh12"
     *
     * receiver decrypt digital signature using public key of sender:
     *  var matches = dec("12jk4hkh12", "pub512");
     *  if matches == message, then signed message is valid (not tampered)
     */
    @Test
    public void shouldVerifyDigitalSignature() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        // given
        final byte[] message = "signedMessage".getBytes(StandardCharsets.UTF_8);
        Signature sig = Signature.getInstance("SHA256withRSA");

        // when sender
        sig.initSign(senderKeyPair.getPrivate());
        sig.update(message);
        byte[] digitalSignatureOfMessage = sig.sign();

        // then receiver
        sig.initVerify(senderKeyPair.getPublic());
        sig.update(message);

        assertTrue(sig.verify(digitalSignatureOfMessage));
    }

    /**
     * That's why we need to rely on a trusted party (like trusted CA for TLS)
     *
     * sender creates:
     *  public/private key pair: ("pub512", "priv12"),
     *  message: "signedMessage"
     *  digital signature: "12jk4hkh12" <- encrypted with PRIVATE key enc("signedMessage", "priv12")
     *
     * man in the middle creates:
     *  public/private key pair: ("pub11111", "priv888888"),
     *  message: "signedMessage" (copy of what he got)
     *  digital signature: "8ksaj12kh" <- encrypted with PRIVATE key enc("signedMessage", "priv888888")
     *
     * receiver gets:
     *  public key of sender: "pub11111"
     *  message: "signedMessage"
     *  digital signature: "8ksaj12kh"
     *
     * receiver decrypt digital signature using public key of man in the middle:
     *  var matches = dec("8ksaj12kh", "pub11111");
     *  if matches == message, then signed message is valid (tampered !!!!!)
     *
     *  We have to be sure that we know and trust the public key we got!
     */
    @Test
    public void shouldVerifyDigitalSignatureWithManInTheMiddleAttack() throws NoSuchAlgorithmException,
            InvalidKeyException, SignatureException {

        // given
        final byte[] message = "signedMessage".getBytes(StandardCharsets.UTF_8);
        Signature sig = Signature.getInstance("SHA256withRSA");

        // when sender
        sig.initSign(senderKeyPair.getPrivate());
        sig.update(message);
        byte[] digitalSignatureOfMessage = sig.sign();

        // when man in the middle enters
        // can read message and provide own signature with public key
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair manInTheMiddleKeyPair = keyPairGenerator.generateKeyPair();

        sig.initSign(manInTheMiddleKeyPair.getPrivate());
        sig.update(message);
        byte[] tamperedDigitalSignatureOfMessage = sig.sign();

        // then receiver
        sig.initVerify(manInTheMiddleKeyPair.getPublic());
        sig.update(message);

        assertTrue(sig.verify(tamperedDigitalSignatureOfMessage));
    }

    @Test
    public void shouldSignAndVerifyUsingCipher() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        final String message = "signedMessage";

        // Key generation
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair key = keyGen.generateKeyPair();

        // sign
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key.getPrivate());
        byte[] messageHash = toSHA512(message);
        byte[] signature = cipher.doFinal(messageHash);

        // verification
        cipher.init(Cipher.DECRYPT_MODE, key.getPublic());
        byte[] decryptedMessageHash = cipher.doFinal(signature);
        assertArrayEquals(decryptedMessageHash, messageHash);
    }

    private byte[] toSHA512(String message) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
        messageDigest.update(message.getBytes(StandardCharsets.UTF_8));
        return messageDigest.digest();
    }

}
