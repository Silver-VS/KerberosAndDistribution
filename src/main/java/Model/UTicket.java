package Model;

import Security.Model.Encryption;

import javax.crypto.SecretKey;
import java.io.Serializable;
import java.util.ArrayList;

/**
 * This class should be used to create, encrypt and decrypt all the Tickets created
 * to transit in the network.
 *
 * @author Silver_VS
 */
public class UTicket implements Serializable {
    private final ArrayList<Ticket> tickets;

    /**
     * Method to initialize the arraylist for a new UTicket.
     */
    public UTicket() {
        tickets = new ArrayList<>();
    }

    public ArrayList<Ticket> getTickets() {
        return tickets;
    }

    public Ticket searchTicket(String id) {
        for (Ticket i : tickets) {
            if (i.getIdTicket().equals(id)) {
                return i;
            }
        }
        return null;
    }

    public void addTicket(Ticket ticket) {
        tickets.add(ticket);
    }

    /**
     * This ticket will be the one that the user sends to the AS at the time of asking for a service.
     * In other words, this should be the first ticket sent in the network.
     */
    public void generateRequest(String userID, String serviceID, String requestedLifetime) {
        Ticket request = new Ticket();
        request.setIdTicket("request");
        request.setFirstId(userID);
        request.setSecondId(serviceID);
        request.setLifetime(requestedLifetime);
        addTicket(request);
    }

    public void generateResponse4User(String firstId, String timeStamp, String lifetime, String key) {
        Ticket response = new Ticket();
        response.setIdTicket("responseToClient");
        response.setFirstId(firstId);
        response.setTimeStamp(timeStamp);
        response.setLifetime(lifetime);
        response.setKey(key);
        addTicket(response);
    }

    public void generateTicket(String nameOfTicket, String firstID, String secondID, String timeStamp, String addressIP,
                               String lifetime, String key) {
        addTicket(
                new Ticket(nameOfTicket, firstID, secondID, addressIP, lifetime, timeStamp, key)
        );
    }

    public void request4TGS(String serviceID) {
        Ticket request = new Ticket();
        request.setIdTicket("request4TGS");
        request.setFirstId(serviceID);
        addTicket(request);
    }

    public void addAuthenticator(String firstID, String addressIP, String timeStamp) {
        Ticket auth = new Ticket();
        auth.setIdTicket("auth");
        auth.setFirstId(firstID);
        auth.setAddressIP(addressIP);
        auth.setTimeStamp(timeStamp);
        addTicket(auth);
    }


    public boolean[] getFilled(Ticket ticket) {
        boolean[] existingFields = new boolean[6];
        existingFields[0] = ticket.isFilledFirstId();
        existingFields[1] = ticket.isFilledSecondId();
        existingFields[2] = ticket.isFilledAddressIP();
        existingFields[3] = ticket.isFilledLifetime();
        existingFields[4] = ticket.isFilledTimeStamp();
        existingFields[5] = ticket.isFilledKey();
        return existingFields;
    }

    public boolean encryptTicket(SecretKey key, String id) {
        try {
            Ticket toEncrypt = searchTicket(id);

            if (toEncrypt == null)
                return false;

            boolean[] existingFields = getFilled(toEncrypt);
            if (existingFields[0])
                toEncrypt.setFirstId(Encryption.symmetricEncrypt(key, toEncrypt.getFirstId()));
            if (existingFields[1])
                toEncrypt.setSecondId(Encryption.symmetricEncrypt(key, toEncrypt.getSecondId()));
            if (existingFields[2])
                toEncrypt.setAddressIP(Encryption.symmetricEncrypt(key, toEncrypt.getAddressIP()));
            if (existingFields[3])
                toEncrypt.setLifetime(Encryption.symmetricEncrypt(key, toEncrypt.getLifetime()));
            if (existingFields[4])
                toEncrypt.setTimeStamp(Encryption.symmetricEncrypt(key, toEncrypt.getTimeStamp()));
            if (existingFields[5])
                toEncrypt.setKey(Encryption.symmetricEncrypt(key, toEncrypt.getKey()));
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public boolean decryptTicket(SecretKey key, String id) {
        try {
            Ticket toDecrypt = searchTicket(id);

            if (toDecrypt == null)
                return false;

            boolean[] existingFields = getFilled(toDecrypt);
            if (existingFields[0]) {
                toDecrypt.setFirstId(Encryption.symmetricDecrypt(key, toDecrypt.getFirstId()));
            }
            if (existingFields[1]) {
                toDecrypt.setSecondId(Encryption.symmetricDecrypt(key, toDecrypt.getSecondId()));
            }
            if (existingFields[2]) {
                toDecrypt.setAddressIP(Encryption.symmetricDecrypt(key, toDecrypt.getAddressIP()));
            }
            if (existingFields[3]) {
                toDecrypt.setLifetime(Encryption.symmetricDecrypt(key, toDecrypt.getLifetime()));
            }
            if (existingFields[4]) {
                toDecrypt.setTimeStamp(Encryption.symmetricDecrypt(key, toDecrypt.getTimeStamp()));
            }
            if (existingFields[5]) {
                toDecrypt.setKey(Encryption.symmetricDecrypt(key, toDecrypt.getKey()));
            }
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public void printTicket(UTicket uTicket) {
        for (Ticket i : uTicket.getTickets()) {
            printTicket(uTicket, i.getIdTicket());
        }
    }

    public void printTicket(UTicket uTicket, String ticketId) {
        Ticket ticket = uTicket.searchTicket(ticketId);
        if (ticket != null) {
            boolean[] filled = uTicket.getFilled(ticket);
            System.out.println("idTicket: " + ticket.getIdTicket());
            if (filled[0]) {
                System.out.println("firstId: " + ticket.getFirstId());
            }
            if (filled[1]) {
                System.out.println("secondId: " + ticket.getSecondId());
            }
            if (filled[2]) {
                System.out.println("addressIP: " + ticket.getAddressIP());
            }
            if (filled[3]) {
                System.out.println("lifetime: " + ticket.getLifetime());
            }
            if (filled[4]) {
                System.out.println("timeStamp: " + ticket.getTimeStamp());
            }
            if (filled[5]) {
                System.out.println("key: " + ticket.getKey());
            }
        }
    }

}
