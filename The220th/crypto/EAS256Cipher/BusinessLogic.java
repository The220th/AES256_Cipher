package The220th.crypto.EAS256Cipher;

import java.io.*;
import The220th.crypto.EAS256Cipher.AES256;
import java.util.Scanner;

public class BusinessLogic
{
    /**
     * Чисто для тестов
     * 
     * @param args
     */
    public static void main(String[] args) throws Exception
    {
        byte[] enBuff = new byte[256];
        //byte[] deBuff = new byte[enBuff.length + enBuff.length];
        byte[] deBuff = new byte[528];
        byte[] buff;
        byte[] enMsg;
        byte[] deMsg;

        FileInputStream fin1 = new FileInputStream("TestFile.zip"); //read
        FileOutputStream fos1 = new FileOutputStream("out"); //write

        System.out.print("Input password: ");
		Scanner in = new Scanner(System.in);
		byte[] keyLoL = AES256.str2ByteKey(in.nextLine());
		System.out.println("Your key: " + AES256.ByteArrToStr(keyLoL));
		AES256 aes256 = new AES256(keyLoL);

        //======================EN
        int i, j;
        j = 0;
        while( (i=fin1.read()) != -1 )
        {
            enBuff[j] = (byte)i;
            j++;
            if(j >= enBuff.length)
            {
                //System.out.println(AES256.ByteArrToStr(enBuff) + " size:" + enBuff.length);
                enMsg = aes256.makeAES256_withSalt(enBuff, AES256.ifENCRYPT);
                System.out.println(AES256.ByteArrToStr(enMsg) + " size:" + enMsg.length);
                fos1.write(enMsg, 0, enMsg.length);
                j = 0;
            }
        }
        if(j < enBuff.length)
        {
            buff = new byte[j];
            for(i = 0; i < j; i++)
                buff[i] = enBuff[i];
            enMsg = aes256.makeAES256_withSalt(buff, AES256.ifENCRYPT);
			System.out.println(AES256.ByteArrToStr(enMsg) + " size:" + enMsg.length);
            fos1.write(enMsg, 0, enMsg.length);
        }
        fin1.close();
        fos1.close();

        System.out.println("\n\n");
        //======================DE
        FileInputStream fin2 = new FileInputStream("out"); //read
        FileOutputStream fos2 = new FileOutputStream("outDe"); //write

        j = 0;
        while( (i=fin2.read()) != -1 )
        {
            deBuff[j] = (byte)i;
            j++;
            if(j >= deBuff.length)
            {
                System.out.println(AES256.ByteArrToStr(deBuff) + " size: " + deBuff.length);
                deMsg = aes256.makeAES256_withSalt(deBuff, AES256.ifDECRYPT);
                fos2.write(deMsg, 0, deMsg.length);
                j = 0;
            }
        }
        if(j < deBuff.length)
        {
            buff = new byte[j];
            for(i = 0; i < j; i++)
                buff[i] = deBuff[i];
			System.out.println(AES256.ByteArrToStr(buff) + " size: " + buff.length);
            deMsg = aes256.makeAES256_withSalt(buff, AES256.ifDECRYPT);
            fos2.write(deMsg, 0, deMsg.length);
        }

        fin2.close();
        fos2.close();
    }
}