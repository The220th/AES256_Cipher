package The220th.crypto.EAS256Cipher;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.SecureRandom;
import java.util.Scanner;

import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.io.ByteArrayOutputStream;
import java.io.*;

import java.security.MessageDigest; 
import java.security.NoSuchAlgorithmException;

/**
 * Штука, которая умеет шифровать с помощью AES 256 бит
 https://coderoad.ru/992019/Java-256-%D0%B1%D0%B8%D1%82%D0%BD%D0%BE%D0%B5-AES-%D1%88%D0%B8%D1%84%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5-%D0%BD%D0%B0-%D0%BE%D1%81%D0%BD%D0%BE%D0%B2%D0%B5-%D0%BF%D0%B0%D1%80%D0%BE%D0%BB%D1%8F
 */
public class AES256
{
	/**
	 * Тут хранится сам ключ шифрования
	 */
	private SecretKey secretKey;

	/**
	 * Нужно для параметра mode метода makeAES256. Показывает, что надо шифровать
	 */
	public static final int ifENCRYPT = Cipher.ENCRYPT_MODE;
	/**
	 * Нужно для параметра mode метода makeAES256. Показывает, что надо дешифровать
	 */
	public static final int ifDECRYPT = Cipher.DECRYPT_MODE;

	/**
	 * Просто пример, как можно пользоваться этим вот всем
	 * 
	 * @param args
	 */
	public static void main(String[] args)
	{
		System.out.print("Input password: ");
		Scanner in = new Scanner(System.in);
		byte[] keyLoL = str2ByteKey(in.nextLine()); // Тоже самое с помощью: keyLoL = AES256.getRndKey256();
		System.out.println("Your key: " + AES256.ByteArrToStr(keyLoL));
		AES256 aes256 = new AES256(keyLoL);

		String ControlMsg = "HelloWorld=\\";
		byte[] enMsg = aes256.makeAES256_withSalt(ControlMsg.getBytes(), AES256.ifENCRYPT);
		byte[] deMsg = aes256.makeAES256_withSalt(enMsg, AES256.ifDECRYPT);
		System.out.println("Control: " + new String(deMsg));
	}

	/*
	public static void main(String[] args)
	{
		int usrC;
		byte[] key = null;
		Scanner in = new Scanner(System.in);

		System.out.println("Generade key? 1 = YES");
		usrC = Integer.valueOf( in.nextLine() );
		if(usrC == 1)
		{
			key = AES256.getRndKey256();
			try(FileOutputStream fos = new FileOutputStream("key", false))
			{
				fos.write(key, 0, key.length);
			}
			catch(IOException ex)
			{ 
				System.out.println(ex.getMessage());
			}
		}

		try(FileInputStream fin = new FileInputStream("key"))
		{
			key = new byte[fin.available()];
			fin.read(key, 0, fin.available());  
		}
		catch(IOException ex)
		{
			System.out.println(ex.getMessage());
		}
		AES256 aes256 = new AES256(key);

		System.out.println("\t1 - Read from EnFile\n\t2 - Write to EnFile");
		usrC = Integer.valueOf( in.nextLine() ); //=(
		if(usrC == 1)
		{
			byte[] buff = null;
			try(FileInputStream fin = new FileInputStream("text"))
			{
				buff = new byte[fin.available()];
				fin.read(buff, 0, fin.available());
			}
			catch(IOException ex)
			{
				System.out.println(ex.getMessage());
			}
			buff = aes256.makeAES256(buff, AES256.ifDECRYPT);
			System.out.println( "There is the text:\n" + new String(buff) );
		}
		else if (usrC == 2)
		{
			byte[] buff = null;
			String S;
			System.out.println("What do you want to write there? Write: ");
			S = in.nextLine();
			try(FileOutputStream fos = new FileOutputStream("text", false))
			{
				buff = aes256.makeAES256(S.getBytes(), AES256.ifENCRYPT);
				fos.write( buff, 0, buff.length);
			}
			catch(IOException ex)
			{
				System.out.println(ex.getMessage());
			}
		}
		in.close();
	}*/



	/**
	 * Конструктор, который генерирует ключ secretKey самостоятельно
	 */
	public AES256()
	{
		try 
		{
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
            this.secretKey = keyGenerator.generateKey();
		}
		catch (NoSuchAlgorithmException e)
		{
            e.printStackTrace();
        }
	}
	/**
	 * Конструктор, который использует в качестве secretKey уже готовый ключ
	 * 
	 * @param key
	 */
	public AES256(byte[] key)
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
	/**
	 * Метод, который возвращает ключ secretKey
	 * 
	 * @return secretKey
	 */
	public byte[] getKey()
	{
		return this.secretKey.getEncoded();
	}

	/**
	 * Генерирует рандомный ключ для шифрования AES 256 бит
	 * @return key 256 бит
	 */
	public static byte[] getRndKey256()
	{
		//ByteArrayOutputStream outStream;
		KeyGenerator keyGenerator;
		byte[] key256 = null;
		try 
		{
			//outStream = new ByteArrayOutputStream();
			keyGenerator = KeyGenerator.getInstance("AES");
			keyGenerator.init(256);
			//outStream.write(keyGenerator.generateKey().getEncoded());
			//key256 = outStream.toByteArray();
			key256 = keyGenerator.generateKey().getEncoded();
		} 
		catch(Exception e)
		{
			e.printStackTrace();
		}
		return key256;
	}

	/**
	 * Из строки pswdStr делает всегда один и тот же ключ для AES-256
	 * 
	 * @param pswdStr - строка, содержащая пароль
	 * @return ключ, соответствующий паролю в pswdStr
	 */
	public static byte[] str2ByteKey(String pswdStr)
	{
		return getSHA256( pswdStr.getBytes() );
	}

	/**
	 * Вот этот метод и шифрует или дешифрует rawMessage в зависимости от cipherMode + ещё используется соль
	 * 
	 * @param rawMessage - сообщение, которое надо зашифровать или расшифровать, представленное в байтах
	 * @param Mode - если AES256.ifENCRYPT (или Cipher.ENCRYPT_MODE==1), то шифрует, если AES256.ifDECRYPT (или Cipher.DECRYPT_MODE==2), то дешифрует
	 * @return зашифрованное или расшифрованное сообщение, представленное в байтах
	 */
	public byte[] makeAES256_withSalt(byte[] rawMessage, int mode) throws IllegalArgumentException
	{
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
			if(mode == AES256.ifENCRYPT)
			{
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
			else if (mode == AES256.ifDECRYPT)
			{
				output = cipher.doFinal(rawMessage); // 0 S 0 S 0 S 0 S 0 S 0 S 0 S 0 S, где S - соль, а 0 - исходные байты
				buff = new byte[rawMessage.length/2];

				for(i = 0, j = 0; i < output.length; i++)
					if(i % 2 == 0)
					{
						buff[j] = output[i];
						j++;
					}
				output = buff;
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
	
	/**
	 * Дополняет строку пробелами так, чтобы ещё длина в битах была кратна 128 битам
	 * 
	 * @param text - строка, которая преобразуется
	 * @return дополненную строку пробелами
	 */
	public static String fillBlock128(String text) 
	{
        int spaceNum = text.getBytes().length%16==0?0:16-text.getBytes().length%16;
        for (int i = 0; i<spaceNum; i++) text += " ";
        return text;
	}

	/**
	 * Дополняет массив байт до длины 256 байт элементом filler. Если в small уже > 256 или 0, или null, то вернёт просто массив, где все элементы - это filler.
	 * 
	 * @param small
	 * @param filler
	 * @return массив, где 256 байт
	 */
	public static byte[] fill256(byte[] small, byte filler) 
	{
		byte[] big = new byte[256];
		int i;
		if(small == null || small.length == 0 || small.length > 256)
			for(i = 0; i < big.length; i++)
				big[i] = filler;
		else
		{
			for(i = 0; i < small.length; i++)
				big[i] = small[i];
			for(; i < big.length; i++)
				big[i] = filler;
		}
		return big;
	}

	/**
	 * Метод, который переводит байты в строку, чтобы можно было хоть как-то вывести массив байт
	 * 
	 * @param Arr - массив байт
	 * @return строка, которая представляет массив байтов
	 */
	public static String ByteArrToStr(byte[] Arr)
	{
		int i;
		StringBuilder builder = new StringBuilder();
		for (i = 0; i < Arr.length; i++)
			builder.append( Byte.valueOf( Arr[i] ).toString() + ( i < Arr.length-1 ?"_":"" ) );
		return builder.toString();
	}

	/**
	 * Метод, который переводит строку в байты; делает обратное действие метода ByteArrToStr
	 * 
	 * @param S - строка, которая будет представлена в виде массива байтов
	 * @return массив байтов, который представляет строку S
	 */
	public static byte[] StrToByteArr(String S)
	{
		int i;
		String[] splitted = S.split("_");
		byte[] res = new byte[ splitted.length ];
		for (i = 0; i < res.length; i++)
			res[i] = Byte.valueOf(splitted[i]);
		return res;
	}

    /**
     * Метод, который вычисляет Хеш-функцию SHA-256 от msg
     * 
     * @param msg - сообщение, от которого вычисляется Хеш-функция
     * @return Хеш-функцию от msg
     */
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