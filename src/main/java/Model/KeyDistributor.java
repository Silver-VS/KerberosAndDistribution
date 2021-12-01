package Model;

import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyDistributor {
    public static void publicSenderSecretReceiver(String receiverHost, int connectionPort, String whosResponding,
                                                  String whoAreYou, String path4KeysRetrieval, String path4KeySaving) throws Exception {

        Socket socket = Messenger.initSocket(receiverHost, connectionPort);

        PublicKey publicKey = KeyMethods.recoverPublic(path4KeysRetrieval, whoAreYou);
        PrivateKey privateKey = KeyMethods.recoverPrivate(path4KeysRetrieval, whoAreYou);

        SecretKey secretKey = Messenger.sendPublicReceiveSecret(socket, publicKey, privateKey);
        KeyMethods.saveSecret(secretKey, path4KeySaving, whoAreYou, whosResponding);
    }

    public static boolean receiver(ServerSocket serverSocket, String whoIsSending,
                                   String whoAreYou, String path4KeySaving) throws Exception {

        System.out.println("Esperando solicitud del " + whoIsSending + ".");
        Socket socket = serverSocket.accept();
        PublicKey publicKey = Messenger.receivePublic(socket);
        KeyMethods.saveKey(publicKey, path4KeySaving, whoIsSending + "Received", true);
        System.out.println("La llave publica ha sido guardada exitosamente");
        SecretKey secretKey = KeyMethods.generateSecretKey();
        KeyMethods.saveSecret(secretKey, path4KeySaving, whoAreYou, whoIsSending);
        System.out.println("La llave secreta ha sido generada exitosamente.");
        return Messenger.respondWithSecret(socket, secretKey, publicKey);
    }
}
