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


class Server {

    private static final int port=9876;

    public static void main(String args[]) throws Exception {

      	DatagramSocketEncrypt serverSocket = new DatagramSocketEncrypt(port);

		byte[] receivepg = new byte[1024];
		byte[] receiveya = new byte[1024];

		while(true) {
			  DatagramPacket receivePacket = new DatagramPacket(receivepg, receivepg.length);

			  serverSocket.receive(receivePacket);
			  String pg = new String(receivePacket.getData());

			  InetAddress IPAddress = receivePacket.getAddress();
			  int port = receivePacket.getPort();

			  String [] e=pg.split(";");
			  String sp=new String(e[0]);
			  String sg=new String(e[1]);

			  BigInteger p=new BigInteger(sp);
			  BigInteger g=new BigInteger(sg);
			  KeyPair key_pair_b;
			  BigInteger xb;
			  BigInteger bigintyb;
			  DHParameterSpec dh_param_spec=new DHParameterSpec(p,g);

			  key_pair_b=Utils.generateDhKeyPair(dh_param_spec);
			  xb=((DHPrivateKey)key_pair_b.getPrivate()).getX();
			  System.out.println("xb: "+xb.toString());

			  bigintyb=((DHPublicKey)key_pair_b.getPublic()).getY();
			  String syb=bigintyb.toString();
			  System.out.println("yb: "+syb);

			  DatagramPacket sendPacket = new DatagramPacket(syb.getBytes(), syb.getBytes().length, IPAddress, port);
			  serverSocket.send(sendPacket);
			  DatagramPacket receivePacket2 = new DatagramPacket(receiveya, receiveya.length);
			  serverSocket.receive(receivePacket2);

			  String sya = new String(Arrays.copyOfRange(receivePacket2.getData(), 0, receivePacket2.getLength()));
			  System.out.println("sya "+sya);
			  BigInteger ya=new BigInteger(sya);
			  System.out.println("ya "+ya.toString());

			  KeyFactory keyFactory = KeyFactory.getInstance("DH");
			  DHPublicKeySpec keySpec=new DHPublicKeySpec(ya, p, g);
			  PublicKey pubKey= keyFactory.generatePublic(keySpec);
			  byte[] Kab_bytes=Utils.computeDhSecret(key_pair_b,pubKey);

			  String algo="AES";
			  String halgo="md5";
			  MessageDigest md=MessageDigest.getInstance(halgo);
			  byte[] hKab_bytes=md.digest(Kab_bytes);
			  SecretKey Kab=new SecretKeySpec(hKab_bytes, algo);
			  System.out.println("Kab "+Kab);


			  System.out.println("Receive communication 1");
			  byte[] mess_recv=new byte[1024];
			  mess_recv=serverSocket.secureReceive(Kab);
			  String str_mess_recv=new String(mess_recv);
			  System.out.println("Decrypted message: "+str_mess_recv);

			  System.out.println("Starting communication 1");
			  BufferedReader br= new BufferedReader (new FileReader("message2.txt"));
			  String message=br.readLine();
			  br.close();
			  byte[] byte_message=message.getBytes();
			  System.out.println("Input message: "+ message);
			  byte [] message_encrypted=new byte[1024];
			  message_encrypted=serverSocket.secureSend(Kab, byte_message, IPAddress, port);
			  System.out.println("\n" + "Encrypted message: "+ByteUtils.bytesToHexString(message_encrypted));

		}
	}
}
