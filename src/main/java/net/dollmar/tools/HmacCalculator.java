package net.dollmar.tools;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class HmacCalculator {

	public static final String SEC_PROVIDER = "BC";

	public static String calculateHmac(
			final String algorithm, 
			final String data, 
			boolean hexEncodedData,
			final String key,
			boolean hexEncodedKey
			) {
		try {
			byte[] dataBytes = (hexEncodedData) ? Hex.decodeHex(data): data.getBytes();
			byte[] keyBytes = (hexEncodedKey) ? Hex.decodeHex(key) : key.getBytes();
			
			Mac mac = Mac.getInstance(algorithm, SEC_PROVIDER);
			SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algorithm);
			mac.init(keySpec);
			byte[] hmacBytes = mac.doFinal(dataBytes);
			
			return Hex.encodeHexString(hmacBytes);
			
		}
		catch (GeneralSecurityException | DecoderException e) {
			return "Error: " + e.getMessage();
		}
	}
	
	
	public static String calculateFileHmac(
			final String algorithm, 
			final String fileName,
			final String key,
			boolean hexEncodedKey) {
		HmacInputStream his = null;
		try {
			byte[] keyBytes = (hexEncodedKey) ? Hex.decodeHex(key) : key.getBytes();
			
			Mac mac = Mac.getInstance(algorithm, SEC_PROVIDER);
			SecretKeySpec keySpec = new SecretKeySpec(keyBytes, algorithm);
			mac.init(keySpec);
			
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
			his = new HmacInputStream(bis, mac); 
			
			while (his.read() != -1) {
				// read the file
			}
			return Hex.encodeHexString(mac.doFinal());
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
