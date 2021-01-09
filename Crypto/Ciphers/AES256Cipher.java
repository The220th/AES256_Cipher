package Crypto.Ciphers;

import java.lang.*;
import java.util.*;
import java.io.*;

import Crypto.Ciphers.ICipher;
import Crypto.Tools.*;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.io.ByteArrayOutputStream;

import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;


public class AES256Cipher implements ICipher
{
	private SecretKey secretKey;
	
	private static final int ifENCRYPT = Cipher.ENCRYPT_MODE;
	private static final int ifDECRYPT = Cipher.DECRYPT_MODE;
	
	private static final int ReadedSizeBytes = 1024;
	
	public static void main(String[] args)
	{
		AES256Cipher aes = new AES256Cipher(AES256Cipher.getRndKey());
		
		try(
				FileInputStream fin = new FileInputStream(".\\TestFile.zip");
				FileOutputStream fos = new FileOutputStream(".\\outEn");
				BufferedInputStream in = new BufferedInputStream(fin);
				BufferedOutputStream out = new BufferedOutputStream(fos);
			)
		{
			aes.encryptStream(fin, fos);
		}
		catch(IOException ex)
		{
			System.out.println(ex.getMessage());
		}
		
		try(
				FileInputStream fin = new FileInputStream(".\\outEn");
				FileOutputStream fos = new FileOutputStream(".\\outDe");
				BufferedInputStream in = new BufferedInputStream(fin);
				BufferedOutputStream out = new BufferedOutputStream(fos);
			)
		{
			aes.decryptStream(fin, fos);
		}
		catch(IOException ex)
		{
			System.out.println(ex.getMessage());
		}
	}
	
	public AES256Cipher(byte[] key)
	{
		try 
		{
			this.secretKey = new SecretKeySpec(key, 0, key.length, "AES");
		} 
		catch (Exception e)
		{
			e.printStackTrace();
        }
	}
	
	public byte[] getKey()
	{
		return this.secretKey.getEncoded();
	}
	
	public String getStrKey()
	{
		return ByteWorker.Bytes2String(this.getKey());
	}
	
	public static byte[] getRndKey()
	{
		KeyGenerator keyGenerator;
		byte[] key256 = null;
		try 
		{
			keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(256);
			key256 = keyGenerator.generateKey().getEncoded();
		} 
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return key256;
	}
	
	/**
	* Шифрует rawMsg
	* Размер массива, возвращаемый этим методом не определён. Используйте ByteWorker.addSizeBefore, ByteWorker.removeSizeBefore и ByteWorker.getSizeBefore
	*
	*/
	public byte[] encrypt(byte[] rawMsg)
	{
		return makeAES256_withSalt(rawMsg, ifENCRYPT);
	}
	
	public byte[] decrypt(byte[] enMsg)
	{
		
		return makeAES256_withSalt(enMsg, ifDECRYPT);
	}
	
	/**
	* Не закрывает потоки
	*/
	public void encryptStream(InputStream rawIn, OutputStream enOut) throws IOException
	{
		byte[] buffRaw = new byte[ReadedSizeBytes];
		byte[] buffEn;
		int n = rawIn.available();
		while(n > ReadedSizeBytes)
		{
			rawIn.read(buffRaw, 0, ReadedSizeBytes);
			buffEn = ByteWorker.addSizeBefore(encrypt(buffRaw));
			enOut.write(buffEn);
			n-=ReadedSizeBytes;
		}
		buffRaw = new byte[n];
		rawIn.read(buffRaw, 0, n);
		byte[] testerino = encrypt(buffRaw);
		buffEn = ByteWorker.addSizeBefore(testerino);
		enOut.write(buffEn);
	}
	
	/**
	* Не закрывает потоки
	*/
	public void decryptStream(InputStream enIn, OutputStream rawOut) throws IOException
	{
		byte[] buffEn;
		int nbuffEn;
		byte[] buffRaw;
		int n = enIn.available();
		
		int sizeOfSize = ByteWorker.numberOfBytes_of_SizeBefore;
		byte[] buffSize = new byte[sizeOfSize];
		
		while(n > 0)
		{
			enIn.read(buffSize, 0, sizeOfSize);
			nbuffEn = ByteWorker.Bytes2Int(buffSize);
			
			buffEn = new byte[nbuffEn];
			enIn.read(buffEn, 0, nbuffEn);
			buffRaw = decrypt(buffEn);
			rawOut.write(buffRaw);
			n-=(nbuffEn+sizeOfSize);
		}
	}
	
	private byte[] makeAES256_withSalt(byte[] rawMessage, int mode) throws IllegalArgumentException
	{
		/*https://coderoad.ru/992019/Java-256-%D0%B1%D0%B8%D1%82%D0%BD%D0%BE%D0%B5-AES-%D1%88%D0%B8%D1%84%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5-%D0%BD%D0%B0-%D0%BE%D1%81%D0%BD%D0%BE%D0%B2%D0%B5-%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8F*/
		
		int i, j, k;
		byte[] output;
		byte[] msg;
		byte[] buff;
		Cipher cipher;
		SecureRandom secRND = new SecureRandom();
		if(rawMessage == null || rawMessage.length == 0)
			throw new IllegalArgumentException("rawMessage must be init and len > 0\n");
		try
		{
            cipher = Cipher.getInstance("AES");
			cipher.init( mode, this.secretKey );
			if(mode == AES256Cipher.ifENCRYPT)
			{
				//System.out.println(ByteWorker.forPrint(rawMessage));
				msg = new byte[ rawMessage.length + rawMessage.length]; // 0 S 0 S 0 S 0 S 0 S 0 S 0 S 0 S, где S - соль, а 0 - исходные байты
				buff = new byte[rawMessage.length];
				secRND.nextBytes(buff);

				for(i = 0, j = 0, k = 0; i < msg.length; i++)
				{
					if(i % 2 == 1)
					{
						msg[i] = buff[j];
						j++;
					}
					else
					{
						msg[i] = rawMessage[k];
						k++;
					}
				}
				//System.out.println("\n\n" + ByteArrToStr(msg) + " size: " + msg.length);
				output = cipher.doFinal(msg);
				//System.out.println(ByteArrToStr(output) + " size: " + output.length + "\n\n");
			}
			else if (mode == AES256Cipher.ifDECRYPT)
			{
				output = cipher.doFinal(rawMessage); // 0 S 0 S 0 S 0 S 0 S 0 S 0 S 0 S, где S - соль, а 0 - исходные байты
				buff = new byte[output.length/2];

				for(i = 0, j = 0; i < output.length; i++)
					if(i % 2 == 0)
					{
						buff[j] = output[i];
						j++;
					}
				output = buff;
				//System.out.println(ByteWorker.forPrint(buff));
			}
			else
			{
				System.out.println("There is no a such mode: " + mode);
				output = null;
			}
            return output;
		} 
		catch (Exception e)
		{
            e.printStackTrace();
            return null;
        }
	}
	
	public static byte[] getSHA256(byte[] msg)
    {  
        MessageDigest md = null;
        byte[] res = null;
        try
        {
            md = MessageDigest.getInstance("SHA-256");
            res = md.digest(msg);
            
        }
        catch(Exception e)
        {
            System.out.println("WOK in getSHA256\n ");
            e.printStackTrace();
        }
        return res;
    }
}