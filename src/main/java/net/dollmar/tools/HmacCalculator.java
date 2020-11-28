package net.dollmar.tools;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;

public class HmacCalculator {

	public static final String SEC_PROVIDER = "BC";


	public static String calculateHmac(
			final String algorithm, 
			final String data, 
			DataLabel dataEncoding,
			final String key,
			DataLabel keyEncoding,
			boolean hexEncodedResult,
			boolean upperCasedResult) 
	{
		try {
			byte[] dataBytes = HashCalculator.dataToBytes(data, dataEncoding);
			if (dataBytes == null) {
				return "Error: Invalid data encoding."; 
			}			
			byte[] keyBytes = HashCalculator.dataToBytes(key, keyEncoding);
			if (keyBytes == null) {
				return "Error: Invalid key encoding."; 
			}			

			
			Mac mac = Mac.getInstance(algorithm, SEC_PROVIDER);
			SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algorithm);
			mac.init(keySpec);
			byte[] hmacBytes = mac.doFinal(dataBytes);
			
			return HashCalculator.bytesToString(hmacBytes, hexEncodedResult, upperCasedResult);
			
		}
		catch (GeneralSecurityException | DecoderException e) {
			return "Error: " + e.getMessage();
		}
	}
	
	
	public static String calculateFileHmac(
			final String algorithm, 
			final String fileName,
			final String key,
			DataLabel keyEncoding,
			boolean hexEncodedResult,
			boolean upperCasedResult) 
	{
		HmacInputStream his = null;
		try {
			byte[] keyBytes = HashCalculator.dataToBytes(key, keyEncoding);
			if (keyBytes == null) {
				return "Error: Invalid key encoding."; 
			}			
			
			Mac mac = Mac.getInstance(algorithm, SEC_PROVIDER);
			SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algorithm);
			mac.init(keySpec);
			
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
			his = new HmacInputStream(bis, mac); 
			
			while (his.read() != -1) {
				// read the file
			}
			byte[] hmacBytes = mac.doFinal();
			
			return HashCalculator.bytesToString(hmacBytes, hexEncodedResult, upperCasedResult);
		}
		catch (GeneralSecurityException | DecoderException | IOException e) {
			return "Error: " + e.getMessage();
		}
		finally {
			if (his != null) {
				try {
					his.close();
				}
				catch(IOException e) {
					//
				}
			}
		}
	}
}
