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
import org.sector67.otp.encoding.SimpleBase16Encoder;
import org.sector67.otp.key.FileKeyStore;
import org.sector67.otp.utils.BaseUtils;

import junit.framework.TestCase;

/**
 * File-based key test suite
 * 
 * @author scott.hasse@gmail.com
 */
public class FileKeyStoreTests extends TestCase {
	FileKeyStore store;

	protected void setUp() throws Exception {
		super.setUp();
		Path tempDir = Files.createTempDirectory("file-test", new FileAttribute[0]);
		FileKeyStore store = new FileKeyStore(tempDir.toString());
		store.init();
		store.generateKey("encrypt-key", 1000);
		store.copyKey("encrypt-key", "decrypt-key");
		this.store = store;
	}

	protected void tearDown() throws Exception {
		super.tearDown();
		store.destroy();
	}


	public void testEncryptDecrypt64() throws EncryptionException {
		String original = "This is a somewhat longer test that includes hello, World";
		OneTimePadCipher cipher = new OneTimePadCipher(store);
		byte[] encrypted = cipher.encrypt("encrypt-key", original);
		String chunked = BaseUtils.getChunkedBase64(encrypted);
		byte[] decoded = BaseUtils.base64ToBytes(chunked);
		String decrypted = cipher.decrypt("decrypt-key", 0, decoded);
		assertEquals("The original test did not match the decrypted text",
				original, decrypted);
	}

	public void testEncryptDecrypt32() throws EncryptionException {
		String original = "This is a somewhat longer test that includes hello, World";
		OneTimePadCipher cipher = new OneTimePadCipher(store);
		byte[] encrypted = cipher.encrypt("encrypt-key", original);
		String chunked = BaseUtils.getChunkedBase32(encrypted);
		byte[] decoded = BaseUtils.base32ToBytes(chunked);
		String decrypted = cipher.decrypt("decrypt-key", 0, decoded);
		assertEquals("The original test did not match the decrypted text",
				original, decrypted);
	}
	
	public void testEncryptDecrypt16() throws EncryptionException {
		String original = "This is a somewhat longer test that includes hello, World";
		OneTimePadCipher cipher = new OneTimePadCipher(store);
		byte[] encrypted = cipher.encrypt("encrypt-key", original);
		SimpleBase16Encoder encoder = new SimpleBase16Encoder();
		encoder.setMinorChunkSeparator(" ");
		String chunked = encoder.encode(encrypted);
		byte[] decoded = encoder.decode(chunked);
		String decrypted = cipher.decrypt("decrypt-key", 0, decoded);
		assertEquals("The original test did not match the decrypted text",
				original, decrypted);
	}
	
}
