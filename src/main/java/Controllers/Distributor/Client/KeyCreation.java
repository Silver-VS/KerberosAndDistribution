package Controllers.Distributor.Client;

import Security.Model.KeyMethods;

public class KeyCreation {
    public static void main(String[] args) throws Exception {

        String projectPath = "C:\\Escuela\\Quinto\\SeguridadWeb\\Kerberos";

        String path4Keys = projectPath + "\\src\\main\\java\\Security\\SecretVault\\Generated\\";

        KeyMethods.keyCreator(path4Keys, "Client");
    }
}
