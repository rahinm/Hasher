package net.dollmar.tools;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class HashCalculator {

	public static final String SEC_PROVIDER = "BC";

	public static String calculateHash(final String algorithm, final String data, boolean hexEncoded) {
		try {
			byte[] dataBytes = (hexEncoded) ? Hex.decodeHex(data) : data.getBytes();

			MessageDigest md = MessageDigest.getInstance(algorithm, SEC_PROVIDER);
			md.update(dataBytes);
			byte[] hashBytes = md.digest();
			
			return Hex.encodeHexString(hashBytes); //					DatatypeConverter.printHexBinary(hashBytes);
			
		}
		catch (GeneralSecurityException | DecoderException e) {
			return "Error: " + e.getMessage();
		}
	}
	
	
	public static String calculateFileHash(final String algorithm, final String fileName) {
		DigestInputStream dis = null;
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm, SEC_PROVIDER);
			BufferedInputStream bis = new BufferedInputStream(new FileInputStream(fileName));
			dis = new DigestInputStream(bis, md); 
			
			while (dis.read() != -1) {
				// read the file
			}
			return Hex.encodeHexString(md.digest());
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
