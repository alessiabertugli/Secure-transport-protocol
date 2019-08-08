public class ByteUtils {

	
	/** Converts a byte array into a hexadecimal string.
	 * @param data the byte array
	 * @return the hexadecimal string */
	public static String bytesToHexString(byte[] data) {
		return bytesToHexString(data,0,data.length);
	}
	

	/** Converts a byte array into a hexadecimal string.
	 * @param buf the byte array
	 * @param off the offset within the array
	 * @param len the length
	 * @return the hexadecimal string */
	public static String bytesToHexString(byte[] buf, int off, int len) {
		StringBuffer sb=new StringBuffer();
		int end=off+len;
		for (int i=off; i<end; i++) {
			sb.append(Integer.toHexString((buf[i]>>4)&0x0f));
			sb.append(Integer.toHexString(buf[i]&0x0f));
		}
		return sb.toString();
	}

	
	/** Converts an hexadecimal string into a byte array.
	 * @param str the string with hexadecimal symbols
	 * @return the byte array */
	public static byte[] hexStringToBytes(String str) {
		int str_len=str.length();
		byte[] data=new byte[str_len/2];
		hexStringToBytes(str,data,0);
		return data;
	}


	/** Converts an hexadecimal string into a byte array.
	 * @param str the string with hexadecimal symbols
	 * @param buf the byte array
	 * @param off the offset within the array
	 * @return the number of bytes */
	public static int hexStringToBytes(String str, byte[] buf, int off) {
		int str_len=str.length();
		for (int i=0; i<str_len; i+=2) buf[off++]=(byte)Integer.parseInt(str.substring(i,i+2),16);
		return str_len/2;
	}

	
	/** Converts a byte array into a binary string.
	 * @param data the byte array
	 * @return the binary string */
	public static String bytesToBinString(byte[] data) {
		return bytesToBinString(data,0,data.length);
	}


	/** Converts a byte array into a binary string.
	 * @param buf the byte array
	 * @param off the offset within the array
	 * @param len the length
	 * @return the binary string */
	public static String bytesToBinString(byte[] buf, int off, int len) {
		StringBuffer sb=new StringBuffer();
		int end=off+len;
		for (int i=off; i<end; i++) {
			int b=buf[i];
			for (int k=7; k>=0; k--) {
				sb.append((b>>k)&0x01);
				//if (k==4) sb.append(" ");
			}
			//if (i<(end-1)) sb.append(" ");
		}
		return sb.toString();
	}  

}
