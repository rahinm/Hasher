package net.dollmar.tools;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class HashCalculator {

	public static final String SEC_PROVIDER = "BC";


	public static byte[] dataToBytes(String data, DataLabel encoding) throws DecoderException {
		switch (encoding) {
		case TEXT: return data.getBytes(Charset.forName("UTF-8")); 
		case HEX: return  Hex.decodeHex(data); 
		case BASE64: return  Base64.getDecoder().decode(data); 
		default:
			return null;
		}
	}
	
	public static String bytesToString(final byte[] bytes, boolean hexEncodedResult, boolean upperCasedResult) {
		String result = null;
		if (hexEncodedResult) {
			result = Hex.encodeHexString(bytes);
			if (upperCasedResult) {
				result = result.toUpperCase();
			}
		}
		else {
			result = Base64.getEncoder().encodeToString(bytes);
		}

		return result;
	}

	
	
	public static String calculateHash(
			final String algorithm, 
			final String data, 
			DataLabel dataEncoding,
			boolean hexEncodedResult,
			boolean upperCasedResult) 
	{
		try {
			byte[] dataBytes = dataToBytes(data, dataEncoding);
			if (dataBytes == null) {
				return "Error: Invalid data encoding."; 
			}

			MessageDigest md = MessageDigest.getInstance(algorithm, SEC_PROVIDER);
			md.update(dataBytes);
			byte[] hashBytes = md.digest();
			return bytesToString(hashBytes, hexEncodedResult, upperCasedResult);

		}
		catch (GeneralSecurityException | DecoderException e) {
			return "Error: " + e.getMessage();
		}
	}


	public static String calculateFileHash(
			final String algorithm, 
			final String fileName,
			boolean hexEncodedResult,
			boolean upperCasedResult) 
	{
		DigestInputStream dis = null;
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm, SEC_PROVIDER);
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
			dis = new DigestInputStream(bis, md); 

			while (dis.read() != -1) {
				// read the file
			}
			byte[] hashBytes = md.digest();
			return bytesToString(hashBytes, hexEncodedResult, upperCasedResult);
		}
		catch (GeneralSecurityException | IOException e) {
			return "Error: " + e.getMessage();
		}
		finally {
			if (dis != null) {
				try {
					dis.close();
				}
				catch(IOException e) {
					//
				}
			}
		}
	}

}
