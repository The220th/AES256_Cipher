package Crypto.Ciphers;

import java.io.*;

public interface ICipher
{
	public abstract byte[] getKey();
	public abstract String getStrKey();
	public static byte[] getRndKey() {return null;}
	
	public abstract byte[] encrypt(byte[] rawMsg);
	public abstract byte[] decrypt(byte[] enMsg);
	
	public abstract void encryptStream(InputStream rawIn, OutputStream enOut) throws IOException;
	public abstract void decryptStream(InputStream enIn, OutputStream rawOut) throws IOException;
}