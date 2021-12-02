package Controllers.Kerberos.Server;

import Model.Messenger;
import Model.Ticket;
import Model.UTicket;
import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.net.Socket;
import java.sql.Timestamp;
import java.time.Instant;

/**
 * @author Silver-VS
 */

public class ProcessRequest {
    public static void processUserRequest(Socket socket, String path4KeyRetrieving, String serviceIPAddress) {
        try {
            UTicket userRequest = Messenger.ticketAccepter(socket);

            if (userRequest == null) {
                System.out.println("Ha ocurrido un error");
                System.exit(-1);
            }

            //  We retrieve our SecretKey with the TGS.
            SecretKey secretKeyServer_TGS = KeyMethods.recoverSecret(path4KeyRetrieving, "Server", "TGS");

            //  We decrypt our ticket with our secret key.
            userRequest.decryptTicket(secretKeyServer_TGS, "serviceTicket");

            Ticket serviceTicket = userRequest.searchTicket("serviceTicket");

            SecretKey sessionKeyClientServer = KeyMethods.convertString2Key(serviceTicket.getKey());

            userRequest.decryptTicket(sessionKeyClientServer, "auth");

            Ticket userAuth = userRequest.searchTicket("auth");


            if (serviceTicket.getFirstId().equals(userAuth.getFirstId())) {
                if (
                        serviceTicket.getSecondId().equals("Server")
                                &&

                                userAuth.getAddressIP().equals("localhost")
//                                userAuth.getAddressIP().equals(socket.getInetAddress().getHostAddress())
                )
                    approveSession(socket, sessionKeyClientServer, serviceIPAddress);
            }
            boolean flag;
            do flag = Messenger.booleanResponder(socket, false); while (!flag);

        } catch (Exception e) {
            System.out.println("Ha ocurrido un error.");
            System.out.println("Error: ");
            e.printStackTrace();
            System.exit(-1);
        }
    }

    public static void approveSession(Socket socket, SecretKey sessionKeyClientServer, String serviceIPAddress) {
        UTicket approved = new UTicket();
        approved.addAuthenticator("ServiceAuth", serviceIPAddress, Timestamp.from(Instant.now()).toString());
        if (approved.encryptTicket(sessionKeyClientServer, "auth"))
            System.out.println("Ticket auth encriptado correctamente con llave de sesi\u00F3n Servidor-Cliente");
        else {
            System.out.println("Ha ocurrido un error al encriptar el ticket auth.");
            System.exit(-1);
        }
        boolean flag;
        do flag = Messenger.ticketResponder(socket, approved); while (!flag);
        System.exit(0);
    }
}