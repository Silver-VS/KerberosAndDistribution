package Model;

import Security.Model.Encryption;
import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Messenger {

    public static Socket initSocket(String receiverHost, int connectionPort) throws IOException {
        //  We indicate the destination of the Ticket, establishing the IP where it will be received and the
        //  "channel" or port where both all comms will be held.
        //  The socket indicated in here must be already running in the receiverHost, or the connection
        //  won't be established.
        return new Socket(receiverHost, connectionPort);
    }

    public static SecretKey sendPublicReceiveSecret(Socket socket, PublicKey keyToSend, PrivateKey privateKey) {
        try {
            KeyObject keyObject = new KeyObject();

            String key2String = KeyMethods.convertAnyKey2String(keyToSend);

            keyObject.setPublicKey(key2String);
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectSender = new ObjectOutputStream(outputStream);
            objectSender.writeObject(keyObject);
            System.out.println("La llave publica ha sido enviada exitosamente.");
            String receivedEncrypted = awaitSecret(socket);
            System.out.println("La llave secreta encriptada ha sido recibida exitosamente.");
            String secretDecrypted = Encryption.privateDecrypt(privateKey, receivedEncrypted);
            System.out.println("Se ha desencriptado exitosamente la llave privada");

            return KeyMethods.convertString2Key(secretDecrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static PublicKey receivePublic(Socket socket) {

        try {
            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectReceiver = new ObjectInputStream(inputStream);
            KeyObject keyObject = (KeyObject) objectReceiver.readObject();
            String receivedString = keyObject.getPublicKey();
            return KeyMethods.convertString2Public(receivedString);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    public static boolean respondWithSecret(Socket socket, SecretKey secretKey, PublicKey publicKey) {
        try {
            String encryptedString = Encryption.publicEncrypt(publicKey, KeyMethods.convertAnyKey2String(secretKey));
            System.out.println("Se ha encriptado exitosamente la llave secreta.");
            KeyObject keyObject = new KeyObject();
            keyObject.setSecretKey(encryptedString);
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectSender = new ObjectOutputStream(outputStream);
            objectSender.writeObject(keyObject);
            socket.close();
            System.out.println("La llave secreta encriptada ha sido enviada exitosamente.");
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public static String awaitSecret(Socket socket) {
        try {

            InputStream inputStream = socket.getInputStream();
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            KeyObject keyObject = (KeyObject) objectInputStream.readObject();
            return keyObject.getSecretKey();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}
