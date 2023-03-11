import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA_256 {

    public static String getSHA256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] messageDigest = md.digest(input.getBytes());
            return convertByteToHex(messageDigest);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static String convertByteToHex(byte[] data) {
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }
}

String input = "Hello, World!";
String hash = SHA256.getSHA256(input);
System.out.println("SHA-256 Hash: " + hash);
