package Controllers.Kerberos.AS;

import Model.Messenger;
import Model.Ticket;
import Model.TimeMethods;
import Model.UTicket;
import Security.Model.Encryption;
import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.net.Socket;
import java.sql.Timestamp;
import java.time.Instant;

/**
 * @author Silver-VS
 */

public class ProcessRequest {

    public static boolean processUserRequest(Socket socket, String path4KeySaving, String path4KeyRetrieving) {
        try {
            UTicket userRequest = Messenger.ticketAccepter(socket);
            if (userRequest == null) {
                System.out.println("Ha ocurrido un error");
                System.exit(-1);
            }
            Ticket ticket = userRequest.searchTicket("request");
            UTicket userResponse = new UTicket();

            System.out.println("Ticket recibido");
            userResponse.printTicket(userRequest);
            System.out.println("Final de ticket recibido");

            SecretKey sessionKeyClientTGS = KeyMethods.generateSecretKey();
            KeyMethods.saveSecret(sessionKeyClientTGS, path4KeySaving, "Client", "TGS");

            Timestamp timestamp = Timestamp.from(Instant.now());
            Timestamp lifetime = new Timestamp(timestamp.getTime() + TimeMethods.getMillis(5,0));

            userResponse.generateResponse4User( // Name of ticket: responseToClient
                    "TGS - Victor", // ID TGS
                    timestamp.toString(), // TS 2
                    lifetime.toString(), // Tiempo de vida 2
                    KeyMethods.convertAnyKey2String(sessionKeyClientTGS)); // K c-tgs

            userResponse.generateTicket(
                    "TGT", // Ticket TGS
                    ticket.getFirstId(), // ID c
                    "TGS - Victor", // ID tgs
                    timestamp.toString(), // TS 2
                    socket.getInetAddress().getHostAddress(), //AD c
                    lifetime.toString(), // Tiempo de vida 2
                    KeyMethods.convertAnyKey2String(sessionKeyClientTGS)); // K c-tgs

            SecretKey secretAS_Client = KeyMethods.recoverSecret(path4KeyRetrieving, "AS", "Client");
            SecretKey secretAS_TGS = KeyMethods.recoverSecret(path4KeyRetrieving, "AS", "TGS");

            if (userResponse.encryptTicket(secretAS_Client, "responseToClient"))
                System.out.println("El ticket responseToClient ha sido encriptado con la llave AS-Client exitosamente.");
            else {
                System.out.println("Ha ocurrido un error al encriptar el ticket responseToClient");
                System.exit(-1);
            }
            if (userResponse.encryptTicket(secretAS_TGS, "TGT"))
                System.out.println("Ticket TGT ha sido encriptado exitosamente con la llave secrete AS-TGS.");
            else {
                System.out.println("Ha ocurrido un error al encriptar el ticket TGT");
                System.exit(-1);
            }
            if (userResponse.encryptTicket(secretAS_Client, "TGT"))
                System.out.println("Ticket TGT ha sido encriptado exitosamente con la llave secrete AS-Client.");
            else {
                System.out.println("Ha ocurrido un error al encriptar el ticket TGT");
                System.exit(-1);
            }

            return Messenger.ticketResponder(socket, userResponse);

        } catch (Exception e) {

            e.printStackTrace();
            return false;
        }
    }

}
