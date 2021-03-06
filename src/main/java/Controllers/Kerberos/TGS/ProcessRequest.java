package Controllers.Kerberos.TGS;

import Model.Messenger;
import Model.Ticket;
import Model.TimeMethods;
import Model.UTicket;
import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.net.Socket;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.Instant;

/**
 * @author Silver-VS
 */

public class ProcessRequest {

    public static boolean processUserRequest(Socket socket, String path4KeyRetrieving, String path4KeySaving) {
        try {
            UTicket userRequest = Messenger.ticketAccepter(socket);

            if (userRequest == null) {
                System.out.println("Ha ocurrido un error al aceptar la petici\u00F3n del usuario.");
                System.exit(-1);
            }

            //  We retrieve our SecretKey with the AS.
            SecretKey secretKeyTGS_AS = KeyMethods.recoverSecret(path4KeyRetrieving, "TGS", "AS");

            //  We decrypt the ticket sent by the AS with our symmetric key.
            if (userRequest.decryptTicket(secretKeyTGS_AS, "TGT"))
                System.out.println("Ticket TGT desencriptado correctamente con llave secreta TGS-AS");
            else {
                System.out.println("Ha ocurrido un error al desencriptar el ticket TGT.");
                System.exit(-1);
            }

            Ticket tgt = userRequest.searchTicket("TGT");

            //  We recover the session key generated by the AS to be able to send a secure response
            SecretKey sessionKeyTGS_Client = KeyMethods.convertString2Key(tgt.getKey());
            KeyMethods.saveSecret(sessionKeyTGS_Client, path4KeyRetrieving, "TGS", "Client");

            if (userRequest.decryptTicket(sessionKeyTGS_Client, "auth"))
                System.out.println("Ticket auth desencriptado correctamente con llave de sesi\u00F3n Cliente-TGS");
            else {
                System.out.println("Ha ocurrido un error al desencriptar el ticket auth.");
                System.exit(-1);
            }

            Ticket userService = userRequest.searchTicket("request4TGS");
            Ticket userAuth = userRequest.searchTicket("auth");

            //  We compare the ID of the client.
            if (tgt.getFirstId().equals(userAuth.getFirstId())) {
                Timestamp lifetime = TimeMethods.string2TimeStamp(tgt.getLifetime());
                Timestamp now = TimeMethods.timeSignature();
                if (now.compareTo(lifetime) < 0){
                    //  We compare the IP address of the client.
                    if (tgt.getAddressIP().equals(socket.getInetAddress().getHostAddress())) {

                        //  We generate a session key for the user to use with the Server.
                        SecretKey sessionKeyClient_Server = KeyMethods.generateSecretKey();
                        KeyMethods.saveSecret(sessionKeyClient_Server, path4KeySaving, "Client", "Server");
                        UTicket userResponse = new UTicket(); // id ticket: responseToClient
                        userResponse.generateResponse4User( //
                                "Server", //  ID v
                                now.toString(), // TS 4
                                lifetime.toString(), //  Tiempo de vida 2
                                KeyMethods.convertAnyKey2String(sessionKeyClient_Server) //  K c-v
                        );

                        Timestamp secondLifetime = new Timestamp(now.getTime() + TimeMethods.getMillis(5,0));

                        userResponse.generateTicket(
                                "serviceTicket",
                                tgt.getFirstId(), // ID c
                                userService.getFirstId(), //  ID v
                                now.toString(),  // TS 4
                                tgt.getAddressIP(), //  AD c
                                secondLifetime.toString(), //  Tiempo de vida 4
                                KeyMethods.convertAnyKey2String(sessionKeyClient_Server) //  K c-v
                        );

                        SecretKey secretTGS_Server =
                                KeyMethods.recoverSecret(
                                        path4KeyRetrieving, "TGS", "Server"
                                );

                        if (userResponse.encryptTicket(sessionKeyTGS_Client, "responseToClient"))
                            System.out.println("El ticket responseToClient ha sido encriptado con la llave TGS-Client exitosamente.");
                        else {
                            System.out.println("Ha ocurrido un error al encriptar el ticket responseToClient");
                            System.exit(-1);
                        }
                        if (userResponse.encryptTicket(secretTGS_Server, "serviceTicket"))
                            System.out.println("El ticket serviceTicket ha sido encriptado con la llave TGS-Server exitosamente.");
                        else {
                            System.out.println("Ha ocurrido un error al encriptar el ticket serviceTicket.");
                            System.exit(-1);
                        }
                        if (userResponse.encryptTicket(sessionKeyTGS_Client, "serviceTicket"))
                            System.out.println("El ticket serviceTicket ha sido encriptado con la llave TGS-Client exitosamente.");
                        else {
                            System.out.println("Ha ocurrido un error al encriptar el ticket serviceTicket.");
                            System.exit(-1);
                        }

                        return Messenger.ticketResponder(socket, userResponse);
                    }
                }
            }

            boolean flag;
            do flag = Messenger.booleanResponder(socket, false); while (!flag);
            return false;

        } catch (Exception e) {
            System.out.println("Error: ");
            e.printStackTrace();
            return false;
        }
    }

}
