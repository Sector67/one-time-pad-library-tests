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

import org.sector67.otp.EncryptionException;
import org.sector67.otp.cipher.OneTimePadCipher;
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
			byte[] encrypted = cipher.encrypt("encrypt-key", original);
			// encode including ECC
			byte[] ecc = ErrorCorrectingUtils.encode(encrypted);
			//flip some bits
			ecc[2] = 0x0;
			ecc[3] = 0x0;
			ecc[4] = 0x0;
			ecc[5] = 0x0;
			String chunked = BaseUtils.getChunkedBase16(ecc);
			byte[] decoded = BaseUtils.base16ToBytes(chunked);
			// decode using ECC
			byte[] errorCorrected = ErrorCorrectingUtils.decode(decoded);
			String decrypted = cipher.decrypt("decrypt-key", errorCorrected);
			assertTrue("The original test did not match the decrypted text",
					original.equals(decrypted));
		} catch (ReedSolomonException e) {
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
			byte[] ecc = ErrorCorrectingUtils.encode(encrypted);
			//flip some bits
			ecc[1] = 0x0;
			ecc[2] = 0x0;
			ecc[3] = 0x0;
			ecc[4] = 0x0;
			ecc[5] = 0x0;
			String chunked = BaseUtils.getChunkedBase16(ecc);
			byte[] decoded = BaseUtils.base16ToBytes(chunked);
			// decode using ECC
			byte[] errorCorrected = ErrorCorrectingUtils.decode(decoded);
			@SuppressWarnings("unused")
			String decrypted = cipher.decrypt("decrypt-key", errorCorrected);
			fail("Too much data was lost, this point should not be reached");
		} catch (ReedSolomonException e) {
			//expected
		}
	}
}
