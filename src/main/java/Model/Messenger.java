package Model;

import Security.Model.Encryption;
import Security.Model.KeyMethods;

import javax.crypto.SecretKey;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Objects;

public class Messenger {

    public static Socket socketInitializer(String receiverHost, int connectionPort) throws IOException {
        //  We indicate the destination of the Ticket, establishing the IP where it will be received and the
        //  "channel" or port where both all comms will be held.
        //  The socket indicated in here must be already running in the receiverHost, or the connection
        //  won't be established.
        return new Socket(receiverHost, connectionPort);
    }

    //  A server socket takes a request and can send a response without the need to start a second socket.
    public static ServerSocket serverSocketInitializer(int receiverPort) {

        try {
            return new ServerSocket(receiverPort);
        } catch (IOException e) {
            return null;
        }
    }

    public static ObjectOutputStream objectSenderInitializer(Socket socket) {
        try {
            //  We state that we are sending something through an outputStream.
            OutputStream outputStream = socket.getOutputStream();
            //  Now we clarify that we are sending an object through said stream.
            return new ObjectOutputStream(outputStream);
        } catch (Exception e){
            System.out.println("Error al obtener OutputStream del socket: " + socket.toString());
            return null;
        }
    }

    public static Socket requestAccepter(ServerSocket serverSocket) {

        try {
            //  Now we will accept incoming messages from the established channel.
            return serverSocket.accept();
        } catch (IOException e) {
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

    public static UTicket ticketSender(String receiverHost, int connectionPort, UTicket ticket) {

        try {
            Socket socket = socketInitializer(receiverHost, connectionPort);

            //  Now we need to send the object through the connection.
            Objects.requireNonNull(objectSenderInitializer(socket)).writeObject(ticket);

            //  We show in the console what are we trying to send.
            System.out.print("\nTicket enviado:\n");
            ticket.printTicket(ticket);
            System.out.print("\ntermina ticket enviado.\n");

            //  So now we think it has been sent, but we need to be sure of it.
            //  We are going to be receiving information from the socket to confirm
            //  the reception of the object.
            InputStream inputStream = socket.getInputStream();
            //  The server will be returning a boolean, which is already serialized, so we can make
            //  use of the already existing methods for sending and receiving booleans.
            ObjectInputStream objectReceiver = new ObjectInputStream(inputStream);
            //  At this point, we are reading the information sent as a response for our request.
            UTicket ticket1 = (UTicket) objectReceiver.readObject();

            System.out.print("\nRecibido en red:\n");
            ticket1.printTicket(ticket1);
            System.out.print("\nTermina recibo en red\n");

            //  Now that we have a response we can close the communication channel.
            socket.close();

            return ticket1;
        } catch (Exception e) {
            System.out.print("\nError al recibir el ticket." +
                    "\nError:");
            e.printStackTrace();
            return null;
        }
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

    public static UTicket ticketAccepter(Socket socket) {

        try {
            //  Once accepted, we are going to need to read the information received.
            InputStream inputStream = socket.getInputStream();
            //  We specify that we will be reading an object from said stream.
            ObjectInputStream objectReceiver = new ObjectInputStream(inputStream);
            //  Now we need to read the Ticket.
            return (UTicket) objectReceiver.readObject();
        } catch (Exception e) {
            System.out.println("No se ha podido recibir el ticket." +
                    "\nError: ");
            e.printStackTrace();
            return null;
        }
    }

    public static boolean booleanResponder(Socket socket, boolean response) {

        try {
            //  We send the response ticket.
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectSender = new ObjectOutputStream(outputStream);
            objectSender.writeBoolean(response);
            //  We can proceed to close the receiving socket.
            socket.close();
            return true;
        } catch (Exception e) {
            System.out.println("\nNo se ha podido enviar una respuesta (boolean responder)." +
                    "\nError: ");
            e.printStackTrace();
            return false;
        }
    }

    public static boolean ticketResponder(Socket socket, UTicket ticketResponse) {

        try {
            //  We send the response ticket.
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectSender = new ObjectOutputStream(outputStream);
            objectSender.writeObject(ticketResponse);

            //  We print the ticket response.
            ticketResponse.printTicket(ticketResponse);
            System.out.println("\nEl ticket ha sido enviado exitosamente.");

            //  We can proceed to close the receiving socket.
            socket.close();
            return true;
        } catch (Exception e) {
            System.out.println("\nHa ocurrido un error al enviar el ticket.");
            System.out.println("Error: ");
            e.printStackTrace();
            return false;
        }
    }

    public static boolean secretResponder(Socket socket, SecretKey secretKey, PublicKey publicKey) {

        try {
            String encryptedString = Encryption.publicEncrypt(publicKey, KeyMethods.convertAnyKey2String(secretKey));
            System.out.println("Se ha encriptado exitosamente la llave secreta.");
            KeyObject keyObject = new KeyObject();
            keyObject.setSecretKey(encryptedString);
            OutputStream outputStream = socket.getOutputStream();
            ObjectOutputStream objectSender = new ObjectOutputStream(outputStream);
            objectSender.writeObject(keyObject);
            socket.close();
            System.out.println("\nLa llave secreta encriptada ha sido enviada exitosamente.");
            return true;
        } catch (Exception e) {
            System.out.println("\nHa ocurrido un error al enviar la llave secreta.");
            System.out.println("Error: ");
            e.printStackTrace();
            return false;
        }
    }
}
