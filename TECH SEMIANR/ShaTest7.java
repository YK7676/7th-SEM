package yk;
/**
* author revati raman and deepali
* basic classes and interfaces for implementing our 
* methodology is provided by java.security.*; package.
*/
import java.security.*;
class ShaTest7 
{
public static void main(String[] a) 
{
 try 
{
 MessageDigest mds = 
MessageDigest.getInstance("SHA1");
 System.out.println("Message digest: ");
 System.out.println(" Used Algorithm = "+mds.getAlgorithm());
 System.out.println(" Provider for the algorithm = "+mds.getProvider());
 System.out.println(" Convert it toString = "+mds.toString());
 String input = "";
 mds.update(input.getBytes()); 
 byte[] output = mds.digest();
 System.out.print("SHA1(\""+input+"\") =");
 System.out.println(" "+bytesToHex(output));
 input = "abcd";
 md.update(input.getBytes()); 
 output = mds.digest();
 System.out.print("SHA1(\""+input+"\") =");
 System.out.println(" "+bytesToHex(output));
 input = "1234567890";
 mds.update(input.getBytes()); 
 output = mds.digest();
 System.out.print("SHA1(\""+input+"\") =");
 System.out.println(" "+bytesToHex(output));
 } 
catch (Exception e) 
{
 System.out.println("Exception: "+e);
}
}
 public static String bytesToHex(byte[] b) 
{
 char hexDigit[] = {'0', '1', '2', '3', '4', '5', '6', '7',
 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
 StringBuffer buffer = new StringBuffer();
 for (int j=0; j<b.length; j++) {
 buf.append(hexDigit[(b[j] >> 4) & 0x0f]);
 buf.append(hexDigit[b[j] & 0x0f]);
}
//return the elements inside the buffer 
 return buffer.toString();
 } 
}