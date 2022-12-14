import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
public class Client1 {
	private ObjectOutputStream sOutput;
	private ObjectInputStream sInput;
	private Socket socket;
	private String server;
	private int port;
	private Cipher cipher1;
	private Cipher cipher2;
	int i = 0,j=0;
	message m;
	SecretKey AESkey;
    PublicKey pK ;
	message toSend;
	static String IV = "AAAAAAAAAAAAAAAA";
	Client1 (String server, int port){ 						
	this.server = server;
	this.port = port;
	}
	public static void main(String[] args) throws IOException, NoSuchAlgorithmException {
		System.out.println("***************************************************************");
		System.out.println("*********************SECURED-CHAT-CLIENT***********************");
		System.out.println("***************************************************************");
		System.out.println("Client has started!!!!!!!");
		String serverAddress;
		int portNumber = 8002;
        serverAddress = "localhost";
		Client1 client = new Client1(serverAddress, portNumber);
		client.generateAESkey();
		client.start();
	}
	void start() throws IOException{
		socket = new Socket(server, port);
		System.out.println("connection accepted " + socket.getInetAddress() + " :"  + socket.getPort());	
		sInput = new ObjectInputStream(socket.getInputStream());
		sOutput = new ObjectOutputStream(socket.getOutputStream());
		new sendToServer().start();
		new listenFromServer().start();
	}
	class listenFromServer extends Thread {
		public void run(){
			while(true){
        try{
            if(j == 0){
                pK = (PublicKey) sInput.readObject();
                j=1;
            }else{
     m = (message) sInput.readObject();
            decryptMessage(m.getData());}
      } catch (Exception e){
       		e.printStackTrace();
              System.out.println("connection closed");
                }
      	}
	}
	}
	class sendToServer extends Thread {
        public void run(){
        	while(true){
        try{
	
        if (i == 0){	
        	toSend = null;
   
    	toSend = new message(encryptAESKey());
		sOutput.writeObject(toSend);
        	i =1;
        	}					   
        else{
        	System.out.println("Client: Enter message > ");
			Scanner sc = new Scanner(System.in);
			String s = sc.nextLine();
			toSend = new message(encryptMessage(s));
			sOutput.writeObject(toSend);
        	}
        } catch (Exception e){
              e.printStackTrace();
                break;
                }
        	}
        }
	}
	void generateAESkey() throws NoSuchAlgorithmException{
	AESkey = null;
	KeyGenerator Gen = KeyGenerator.getInstance("AES");
	Gen.init(128);
	AESkey = Gen.generateKey();
	System.out.println("Genereated the AES key : " + AESkey.toString());
	}
	private byte[] encryptAESKey (){
		cipher1 = null;
    	byte[] key = null;
  	  try
  	  { 
		 pK = readPublicKeyFromFile("public.key");	
	     System.out.println("Encrypting the AES key using RSA Public Key:\n" + pK);
   	     cipher1 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
   	     cipher1.init(Cipher.ENCRYPT_MODE, pK );
   	     key = cipher1.doFinal(AESkey.getEncoded());  
   	     i = 1;
   	 	}
   	 catch(Exception e ) {
    	    System.out.println ( "" + e.getMessage() );
    	    e.printStackTrace();
   	 		}
  	  return key;
  	  } 
		private byte[] encryptMessage(String s) throws NoSuchAlgorithmException, NoSuchPaddingException, 
							InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, 
											BadPaddingException{
		cipher2 = null;
    	byte[] cipherText = null;
    	cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
    	cipher2.init(Cipher.ENCRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()) );
    	cipherText = cipher2.doFinal(s.getBytes());
   	   return cipherText;
	}
		private void decryptMessage(byte[] encryptedMessage) {
	        cipher2 = null;
	        try
	        {
	            cipher2 = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	            cipher2.init(Cipher.DECRYPT_MODE, AESkey, new IvParameterSpec(IV.getBytes()));
	             byte[] msg = cipher2.doFinal(encryptedMessage);		            
	             System.out.println("Message From Server   >> " + new String(msg));
	             System.out.println("Client: Enter message > ");
	        }    
	        catch(Exception e)
	         {
	        	e.getCause();
	        	e.printStackTrace();
	        	System.out.println ( ""  + e.getMessage() );
	            }
	    }
	public void closeSocket() {
		try{
	if(sInput !=null) sInput.close();
	if(sOutput !=null) sOutput.close();
	if(socket !=null) socket.close();
		}catch (IOException ioe){
			}
		}
	PublicKey readPublicKeyFromFile(String fileName) throws IOException {
		FileInputStream in = new FileInputStream(fileName);
		ObjectInputStream oin =  new ObjectInputStream(new BufferedInputStream(in));
			 try {
			   BigInteger m = (BigInteger) oin.readObject();
			   BigInteger e = (BigInteger) oin.readObject();
			   RSAPublicKeySpec keySpecifications = new RSAPublicKeySpec(m, e); 
			   KeyFactory kF = KeyFactory.getInstance("RSA");
			   PublicKey pubK = kF.generatePublic(keySpecifications);
			   return pubK;
			 } catch (Exception e) {
				   throw new RuntimeException("Some error in reading public key", e);
			 } finally {
			   oin.close();
			 }
		   }
		}
  



