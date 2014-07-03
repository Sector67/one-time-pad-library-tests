/*
 * Copyright 2014 individual contributors as indicated by the @author 
 * tags
 * 
 * This is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software.  If not, see <http://www.gnu.org/licenses/>. 
 */

package org.sector67.otp.test;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;

import org.apache.commons.codec.EncoderException;
import org.sector67.otp.EncryptionException;
import org.sector67.otp.cipher.OneTimePadCipher;
import org.sector67.otp.encoding.EncodingException;
import org.sector67.otp.encoding.ErrorCorrectingBase16Encoder;
import org.sector67.otp.key.FileKeyStore;
import org.sector67.otp.utils.BaseUtils;
import org.sector67.otp.utils.ErrorCorrectingUtils;

import junit.framework.TestCase;

import com.google.zxing.common.reedsolomon.ReedSolomonException;

/**
 * Error correction code test suite
 * 
 * @author scott.hasse@gmail.com
 */
public class ECCTest extends TestCase {

	private FileKeyStore store;
	
	protected void setUp() throws Exception {
		super.setUp();
		Path tempDir = Files.createTempDirectory("file-test", new FileAttribute[0]);
		FileKeyStore store = new FileKeyStore(tempDir.toString());
		store.generateKey("encrypt-key", 1000);
		store.copyKey("encrypt-key", "decrypt-key");
		this.store = store;
	}

	protected void tearDown() throws Exception {
		super.tearDown();
		store.destroy();
	}

	public void testErrorCorrection1() throws EncryptionException {
		try {
			String original = "I am testing ECC by losing some data on purpose";
			OneTimePadCipher cipher = new OneTimePadCipher(store);
			ErrorCorrectingBase16Encoder encoder = new ErrorCorrectingBase16Encoder();

			byte[] encrypted = cipher.encrypt("encrypt-key", original);

			
			String chunked = encoder.encode(encrypted);
			
			//flip some bits to introduce errors
			chunked = chunked.replaceFirst("A", "0");
			chunked = chunked.replaceFirst("A", "0");

			byte[] decoded = encoder.decode(chunked);
			// decode using ECC
			//byte[] errorCorrected = ErrorCorrectingUtils.decode(decoded);
			String decrypted = cipher.decrypt("decrypt-key", decoded);
			assertEquals("The original test did not match the decrypted text", original, decrypted);
		} catch (EncodingException e) {
			fail("Exception caught:" + e);
		}
	}
	
	/*
	 * This test should lose too much data
	 */
	public void testEncryptDecrypt64() throws EncryptionException {
		try {
			String original = "small";
			OneTimePadCipher cipher = new OneTimePadCipher(store);
			byte[] encrypted = cipher.encrypt("encrypt-key", original);
			// encode including ECC
			ErrorCorrectingBase16Encoder encoder = new ErrorCorrectingBase16Encoder();

			String ecc = encoder.encode(encrypted);
			//flip some bits
			ecc = ecc.replaceAll("A", "0");
			ecc = ecc.replaceAll("B", "0");
			ecc = ecc.replaceAll("C", "0");
			ecc = ecc.replaceAll("D", "0");

			byte[] decoded = encoder.decode(ecc);
			@SuppressWarnings("unused")
			String decrypted = cipher.decrypt("decrypt-key", decoded);
			fail("Too much data was lost, this point should not be reached");
		} catch (EncodingException e) {
			//expected
		}
	}
}
