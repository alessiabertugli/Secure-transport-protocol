import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;


public class DatagramSocketEncrypt extends DatagramSocket{
	
	public final byte[] iv = new byte[] {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
	
	public DatagramSocketEncrypt() throws IOException {
		super();
	}
	public DatagramSocketEncrypt(int port) throws IOException {
		super(port);

	}
	
	public byte[] secureSend(SecretKey Kab, byte[] plaintext, InetAddress IPAddress, int port) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, IOException{
		byte[] ciphertext=new byte[1024];

	    Cipher AesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
	    AesCipher.init(Cipher.ENCRYPT_MODE, Kab, ivParameterSpec);
	    ciphertext=AesCipher.doFinal(plaintext);
	   //System.out.println("ciphertext: "+ByteUtils.bytesToHexString(ciphertext)+" ("+ciphertext.length+" bytes)");
	    
	    DatagramPacket p = new DatagramPacket(ciphertext, ciphertext.length, IPAddress, port);
	    send(p);
	    
		return ciphertext;
	}

	public byte[] secureReceive(SecretKey Kab) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, IOException{
		byte[] plaintext=new byte[1024];
		byte [] byte_cipher=new byte[1024];
		
		DatagramPacket p = new DatagramPacket(byte_cipher, byte_cipher.length);
        receive(p);
		int length=p.getLength();

		Cipher AesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
	    AesCipher.init(Cipher.DECRYPT_MODE, Kab, ivParameterSpec);
	    plaintext= AesCipher.doFinal(byte_cipher, 0, length);
	    //System.out.println("plaintext: "+ByteUtils.bytesToHexString(plaintext)+" ("+plaintext.length+" bytes)");
	    
	    return plaintext;
	}
}
