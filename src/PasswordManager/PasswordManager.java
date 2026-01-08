package PasswordManager;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.*;

public class PasswordManager {

    private static final String AES_ALGO = "AES/CBC/PKCS5Padding";
    private static final String KDF_ALGO = "PBKDF2WithHmacSHA256";

    private static final byte[] SALT = "SecureSalt123".getBytes();
    private static final int ITERATIONS = 65536;
    private static final int KEY_LENGTH = 256;

    private final Map<String, String> passwordStore = new HashMap<>();
    private final SecretKey secretKey;

    public PasswordManager(String masterPassword) throws Exception {
        this.secretKey = generateKey(masterPassword);
    }

    public static void main(String[] args) throws Exception {

        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter Master Password: ");
        String masterPassword = scanner.nextLine();

        PasswordManager manager = new PasswordManager(masterPassword);

        while (true) {
            System.out.println("\n1. Add Password");
            System.out.println("2. Retrieve Password");
            System.out.println("3. Exit");
            System.out.print("Choose option: ");

            int choice = scanner.nextInt();
            scanner.nextLine();

            switch (choice) {
                case 1 -> {
                    System.out.print("Site: ");
                    String site = scanner.nextLine();
                    System.out.print("Password: ");
                    String password = scanner.nextLine();
                    manager.addPassword(site, password);
                }
                case 2 -> {
                    System.out.print("Site: ");
                    String site = scanner.nextLine();
                    System.out.println("Password: " + manager.getPassword(site));
                }
                case 3 -> System.exit(0);
                default -> System.out.println("Invalid option");
            }
        }
    }

    /* ---------------- CORE METHODS ---------------- */

    public void addPassword(String site, String password) {
        try {
            passwordStore.put(site, encrypt(password));
            System.out.println("Password saved securely.");
        } catch (Exception e) {
            System.out.println("Encryption failed.");
        }
    }

    public String getPassword(String site) {
        try {
            String encrypted = passwordStore.get(site);
            if (encrypted == null) return "No entry found.";
            return decrypt(encrypted);
        } catch (Exception e) {
            return "Decryption failed.";
        }
    }

    /* ---------------- SECURITY METHODS ---------------- */

    private SecretKey generateKey(String password) throws Exception {
        KeySpec spec = new PBEKeySpec(password.toCharArray(), SALT, ITERATIONS, KEY_LENGTH);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(KDF_ALGO);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    private String encrypt(String data) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGO);

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new IvParameterSpec(iv));

        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(iv) + ":" +
               Base64.getEncoder().encodeToString(encrypted);
    }

    private String decrypt(String encryptedData) throws Exception {
        String[] parts = encryptedData.split(":");
        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] encrypted = Base64.getDecoder().decode(parts[1]);

        Cipher cipher = Cipher.getInstance(AES_ALGO);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
        return new String(cipher.doFinal(encrypted));
    }
}
