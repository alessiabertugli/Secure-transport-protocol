import java.io.BufferedReader;
import java.io.FileReader;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;


class Client {

	private static InetAddress IPAddress;
	private static final int port=9876;
	
   	public static void main(String args[]) throws Exception {

   		IPAddress=InetAddress.getByName("localhost");
      	DatagramSocketEncrypt clientSocket = new DatagramSocketEncrypt();
      	
		BigInteger p;
		BigInteger g;
		DHParameterSpec dh_param_spec= Utils.generateDhParamenters(512);
		p=dh_param_spec.getP();
		g=dh_param_spec.getG();
		
		String s1=p.toString()+";";
		String s2=g.toString()+";";
		String s3=s1.concat(s2);

		DatagramPacket sendPacket = new DatagramPacket(s3.getBytes(), s3.getBytes().length, IPAddress, port);
		clientSocket.send(sendPacket);

		byte [] pubKeyb=new byte[1024];
		DatagramPacket receivePacket = new DatagramPacket(pubKeyb, pubKeyb.length);
		clientSocket.receive(receivePacket);
		String syb = new String(Arrays.copyOfRange(receivePacket.getData(), 0, receivePacket.getLength()));

   		KeyPair key_pair_a;
   		BigInteger xa;
   		BigInteger intya;
   		
   		key_pair_a=Utils.generateDhKeyPair(dh_param_spec);
   		xa=((DHPrivateKey)key_pair_a.getPrivate()).getX();
   		System.out.println("xa: "+xa.toString());

   		intya=((DHPublicKey)key_pair_a.getPublic()).getY();
 		String sya=intya.toString();	
 		System.out.println("ya: "+sya);
        
		DatagramPacket sendPacket2 = new DatagramPacket(sya.getBytes(), sya.getBytes().length, IPAddress, port);
		clientSocket.send(sendPacket2);

		BigInteger yb=new BigInteger(syb);
		System.out.println("yb "+yb);
		KeyFactory keyFactory = KeyFactory.getInstance("DH");
		DHPublicKeySpec keySpec=new DHPublicKeySpec(yb, p, g);
        PublicKey pubKey= keyFactory.generatePublic(keySpec);

		byte[] Kab_bytes=Utils.computeDhSecret(key_pair_a,pubKey);
        String algo="AES";
        String halgo="md5";		
		MessageDigest md=MessageDigest.getInstance(halgo);			
		byte[] hKab_bytes=md.digest(Kab_bytes);
		SecretKey Kab=new SecretKeySpec(hKab_bytes, algo);
		System.out.println("Kab "+Kab);
		
		
		System.out.println("Strarting communication 1");
        BufferedReader br= new BufferedReader (new FileReader("message.txt"));
		String message=br.readLine();
		br.close();
		byte[] byte_message=message.getBytes();
		System.out.println("Input message: "+ message);
		byte [] message_encrypted=new byte[1024];
		message_encrypted=clientSocket.secureSend(Kab, byte_message, IPAddress, port);
		System.out.println("Encrypted message: "+ByteUtils.bytesToHexString(message_encrypted));
		
		System.out.println("Receive communication 2");
		byte[] mess_recv=new byte[1024];
		mess_recv=clientSocket.secureReceive(Kab);
		String str_mess_recv=new String(mess_recv);
		System.out.println("Decrypted message: "+str_mess_recv);
         
		clientSocket.close();
		
    }

}