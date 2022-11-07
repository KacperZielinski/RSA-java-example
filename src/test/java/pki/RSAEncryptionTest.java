package pki;

import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class RSAEncryptionTest {

    @Test
    public void shouldEncryptAndDecryptRSACypher() throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        final String message = "secret to hide";

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.genKeyPair();

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        byte[] messageHash = toSHA256(message);
        byte[] encryptedHash = cipher.doFinal(messageHash);

        Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher2.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte[] decryptedHash = cipher2.doFinal(encryptedHash);

        assertEquals(Arrays.toString(decryptedHash), Arrays.toString(messageHash));
    }

    private byte[] toSHA256(String message) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(message.getBytes(StandardCharsets.UTF_8));
        return messageDigest.digest();
    }
}
