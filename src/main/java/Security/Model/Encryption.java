package Security.Model;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class Encryption {

    public static String encrypt(Cipher encryptCipher, String toEncrypt) throws Exception {
        byte[] bytesToEncrypt = toEncrypt.getBytes(StandardCharsets.UTF_8);
        byte[] bytesEncrypted = encryptCipher.doFinal(bytesToEncrypt);
        bytesEncrypted = Base64.getEncoder().encode(bytesEncrypted);
        return new String(bytesEncrypted);
    }

    public static String decrypt(Cipher decryptCypher, String toDecrypt) throws Exception {
        byte[] bytesToDecrypt = Base64.getDecoder().decode(toDecrypt.getBytes());
//        byte[] bytesToDecrypt = toDecrypt.getBytes();
        byte[] bytesDecrypted = decryptCypher.doFinal(bytesToDecrypt);
        return new String(bytesDecrypted);
    }

    public static String publicEncrypt(PublicKey publicKey, String toEncrypt) throws Exception {
        Cipher encryptCypher = Cipher.getInstance("RSA");
        encryptCypher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encrypt(encryptCypher, toEncrypt);
    }

    public static String privateDecrypt(PrivateKey privateKey, String toDecrypt) throws Exception {
        Cipher decryptCypher = Cipher.getInstance("RSA");
        decryptCypher.init(Cipher.DECRYPT_MODE, privateKey);
        return decrypt(decryptCypher, toDecrypt);
    }

    public static String symmetricEncrypt(SecretKey secretKey, String toEncrypt) throws Exception {
        Cipher encryptCypher = Cipher.getInstance("DES");
        encryptCypher.init(Cipher.ENCRYPT_MODE, secretKey);
        return encrypt(encryptCypher, toEncrypt);
    }

    public static String symmetricDecrypt(SecretKey secretKey, String toDecrypt) throws Exception {
        Cipher decryptCypher = Cipher.getInstance("DES");
        decryptCypher.init(Cipher.DECRYPT_MODE, secretKey);
        return decrypt(decryptCypher, toDecrypt);
    }
}
