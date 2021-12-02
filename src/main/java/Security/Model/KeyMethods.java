package Security.Model;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class KeyMethods {

    public static void keyCreator(String directoryPath, String whoAreYou) throws Exception {

        String publicAddress = directoryPath + "public" + whoAreYou + ".key";
        String privateAddress = directoryPath + "private" + whoAreYou + ".key";

        KeyPairGenerator generatorRSA = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = generatorRSA.generateKeyPair();

        saveKey(keyPair.getPublic(), publicAddress);
        saveKey(keyPair.getPrivate(), privateAddress);
        System.out.println("Llave del " + whoAreYou + " fue creada exitosamente.");
    }

    public static void saveKey(Key key, String directoryPath, String whoseKey , boolean isPublic) throws Exception {
        String kindOfKey;
        if (isPublic) kindOfKey = "public"; else kindOfKey = "private";
        String address = directoryPath + kindOfKey + whoseKey + ".key";
        saveKey(key, address);
    }

    public static SecretKey generateSecretKey() throws Exception{
        return KeyGenerator.getInstance("DES").generateKey();
    }

    public static void saveKey(Key key, String fileAddress) throws Exception{

        byte[] keyBytes = key.getEncoded();
        FileOutputStream stream = new FileOutputStream(fileAddress);
        stream.write(keyBytes);
        stream.close();
    }

    public static void saveSecret(SecretKey key, String path, String owner,String withWho) throws Exception {
        String fileAddress = path + "Symmetric-" + owner + "-" + withWho + ".key";
        saveKey(key, fileAddress);
    }

    public static KeySpec recoverKey(boolean isPublic, String path, String whosKey) throws Exception{

        String fileAddress;
        if (isPublic) fileAddress = path + "public";
        else fileAddress = path + "private";

        fileAddress = fileAddress + whosKey + ".key";

        byte[] bytes = readFromSomething(fileAddress);

        if (isPublic) return new X509EncodedKeySpec(bytes);
        else return new PKCS8EncodedKeySpec(bytes);
    }

    public static SecretKey recoverSecret(String path, String whoAreYou,String withWho) throws Exception {
        String fileAddress = path + "Symmetric-" + whoAreYou + "-" + withWho + ".key";
        byte[] bytes = readFromSomething(fileAddress);
        return new SecretKeySpec(bytes, "DES");
    }

    public static PrivateKey recoverPrivate(String path, String whosKey) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpecPrivate = recoverKey(false, path, whosKey);
        return keyFactory.generatePrivate(keySpecPrivate);
    }

    public static PublicKey recoverPublic(String path, String whosKey) throws Exception{
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpecPublic = recoverKey(true, path, whosKey);
        return keyFactory.generatePublic(keySpecPublic);
    }

    public static String convertAnyKey2String(Key key) {
        byte[] keyEncoded = key.getEncoded();
        return Base64.getEncoder().encodeToString(keyEncoded);
    }

    public static PublicKey convertString2Public(String keyInString) throws Exception{
        byte[] decodedKey = Base64.getDecoder().decode(keyInString);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        KeySpec keySpec = new X509EncodedKeySpec(decodedKey);
        return  keyFactory.generatePublic(keySpec);
    }

    public static SecretKey convertString2Key(String keyInString) {
        byte[] decodedKey = Base64.getDecoder().decode(keyInString);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES");
    }

    public static byte[] readFromSomething(String address) throws Exception{
        FileInputStream stream = new FileInputStream(address);
        byte[] bytes = new byte[stream.available()];
        stream.read(bytes);
        stream.close();
        return bytes;
    }
}
