import java.security.MessageDigest;

public class SHAExample {
    public static void main(String[] args) throws Exception {
        String input = "example input";

        MessageDigest digest = MessageDigest.getInstance("SHA");
        byte[] hash = digest.digest(input.getBytes());

        StringBuilder hexString = new StringBuilder();
        for (byte b : hash) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        System.out.println("The SHA hash of the input is: " + hexString.toString());
    }
}
