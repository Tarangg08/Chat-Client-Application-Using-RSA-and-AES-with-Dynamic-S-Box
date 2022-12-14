import java.io.*;

class aestest{
    public static String toHexString(byte[] ba) {
    StringBuilder str = new StringBuilder();
    for(int i = 0; i < ba.length; i++)
        str.append(String.format("%x", ba[i]));
    return str.toString();
}

public static String fromHexString(String hex) {
    StringBuilder str = new StringBuilder();
    for (int i = 0; i < hex.length(); i+=2) {
        str.append((char) Integer.parseInt(hex.substring(i, i + 2), 16));
    }
    return str.toString();
}
public static void main(String[] args){
    
		   String key="01234567890123450123456789012444";
           String s="hello";
           System.out.println(s.length());
           int k=s.length();
           if(k<16){
               for(int i=0;i<(16-k);i++){
               s=s.concat("-");
               }
           }
           String st=toHexString(s.getBytes());
	       AES aes= new AES(st,key);
           String et=aes.encrypt();
           System.out.println(et);
           AES aes1= new AES(et,key);
           String pt=aes.decrypt();
           pt=fromHexString(pt);
           System.out.println(pt.replaceAll("-*$",""));
	}
    }