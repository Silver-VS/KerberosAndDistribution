package Controllers.Kerberos.AS;

import Model.Messenger;

import java.net.ServerSocket;

public class Controller {

    /**
     * @author Silver-VS
     */

    public static void main(String[] args) {

        int receivingPort = 1121;
        String projectPath = "C:\\Escuela\\Quinto\\SeguridadWeb\\Kerberos";

        String path4SecretKeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";
        String path4SecretKeyComms = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        ServerSocket serverSocket = Messenger.serverSocketInitializer(receivingPort);

        if (serverSocket == null) {
            System.out.println("No se ha podido iniciar el Servidor.");
            System.exit(-1);
        }

        System.out.println("AS iniciado.");

        do {
            System.out.println("En espera de petici\u00F3n...");
            if (
                    ProcessRequest.processUserRequest(
                            Messenger.requestAccepter(serverSocket),
                            path4SecretKeySaving, path4SecretKeyComms
                    )
            ) {
                System.out.println("Respuesta enviada del AS al cliente.");
            } else {
                System.out.println("Ha ocurrido un error en la respuesta.");
            }
        } while (!serverSocket.isClosed());
    }

}
