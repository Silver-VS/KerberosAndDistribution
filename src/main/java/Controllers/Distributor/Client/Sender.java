package Controllers.Distributor.Client;

import Model.KeyDistributor;

public class Sender {
    public static void main(String[] args) throws Exception {

        String projectPath = "C:\\Escuela\\Quinto\\SeguridadWeb\\Kerberos";
        int connectionPort = 5521;

        String whoAmI = "Client";
        String receiverHost = "localhost";
        String receiverName = "AS";
        String path4KeyRetrieval = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";
        String path4KeySaving = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Connection\\";

        KeyDistributor.publicSenderSecretReceiver(receiverHost, connectionPort, receiverName, whoAmI,
                path4KeyRetrieval, path4KeySaving);
    }
}