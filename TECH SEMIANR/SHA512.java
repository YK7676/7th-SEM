import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA512 {
    public static String getSHA512(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-512");
            byte[] messageDigest = md.digest(input.getBytes());
            StringBuilder hexString = new StringBuilder();
            for (byte b : messageDigest) {
                hexString.append(String.format("%02x", b));
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static void main(String[] args) {
        String input = "TECHNICALSEMINAR";
        System.out.println(getSHA512(input));
    }
}