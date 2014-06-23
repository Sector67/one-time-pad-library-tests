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
import java.util.Arrays;

import org.sector67.otp.EncryptionException;
import org.sector67.otp.cipher.OneTimePadCipher;
import org.sector67.otp.key.FileKeyStore;
import org.sector67.otp.key.KeyException;

import junit.framework.TestCase;

/**
 * General cipher tests with file-based keys
 * 
 * @author scott.hasse@gmail.com
 */
public class OneTimePadCipherFileTest extends TestCase {

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

	public void testEncryptDecrypt() throws EncryptionException {
		String original = "Hello, World";
		OneTimePadCipher cipher = new OneTimePadCipher(store);
		byte[] encrypted = cipher.encrypt("encrypt-key", original);
		String decrypted = cipher.decrypt("decrypt-key", encrypted);
		assertTrue("The original text did not match the encrypted text", original.equals(decrypted));
	}
	/*
	 * Tests to make sure the key is being cleared
	 */
	public void testClearKey() throws EncryptionException {
			String original = "I am going to clear the key after encrypting and decrypting";
			OneTimePadCipher cipher = new OneTimePadCipher(store);
			byte[] encrypted = cipher.encrypt("encrypt-key", original);
			String decrypted = cipher.decrypt("decrypt-key", encrypted);
			assertEquals("The original text did not match the decrypted text", original, decrypted);
			//re-decrypt should not work
			decrypted = cipher.decrypt("decrypt-key", encrypted);
			assertFalse("The original should now not match the decrypted text", original.equals(decrypted));
			//re-encrypt should give a different value as well
			byte[] encrypted2 = cipher.encrypt("encrypt-key", original);
			assertFalse("The original should now not match the encrypted text", Arrays.equals(encrypted, encrypted2));

	}
	
	public void testKeyOverrun() throws Exception {
		try {
		String original = "This is some text longer than the key";
		Path tempDir = Files.createTempDirectory("file-test", new FileAttribute[0]);
		FileKeyStore s = new FileKeyStore(tempDir.toString());
		s.generateKey("encrypt-key", 10);
		s.copyKey("encrypt-key", "decrypt-key");
		OneTimePadCipher cipher = new OneTimePadCipher(s);
		@SuppressWarnings("unused")
		byte[] encrypted = cipher.encrypt("encrypt-key", original);
		fail("Key overrun should have happened and a key exception should have been thrown");
		} catch (KeyException e) {
			//should be thrown, pass
		}
	}
}
