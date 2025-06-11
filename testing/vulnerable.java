import java.util.Random;

public class Vulnerable {
    // Hard-coded password
    private static final String DB_PASSWORD = "admin123";

    // Insecure random number generator
    public static int generateToken() {
        Random random = new Random(); // Insecure for cryptographic purposes
        return random.nextInt(1000);
    }

    public static void main(String[] args) {
        System.out.println("Token: " + generateToken());
        System.out.println("DB Password: " + DB_PASSWORD);
    }
}