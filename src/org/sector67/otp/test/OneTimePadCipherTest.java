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

import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Random;

import org.sector67.otp.EncryptionException;
import org.sector67.otp.cipher.CipherException;
import org.sector67.otp.cipher.OneTimePadCipher;
import org.sector67.otp.encoding.EncodingException;
import org.sector67.otp.encoding.SimpleBase16Encoder;
import org.sector67.otp.key.InMemoryKeyStore;
import org.sector67.otp.key.KeyStore;
import org.sector67.otp.utils.BaseUtils;

import junit.framework.TestCase;

/**
 * General cipher tests with in-memory keys
 * 
 * @author scott.hasse@gmail.com
 */
public class OneTimePadCipherTest extends TestCase {
	private KeyStore store;

	protected void setUp() throws Exception {
		super.setUp();
		InMemoryKeyStore store = new InMemoryKeyStore();
		store.generateKey("encrypt-key", 1000);
		store.copyKey("encrypt-key", "decrypt-key");
		this.store = store;
	}

	protected void tearDown() throws Exception {
		super.tearDown();
	}

	public void testEncryptDecrypt() throws EncryptionException {
		String original = "Hello, World";
		InMemoryKeyStore s = new InMemoryKeyStore();
		byte[] keybytes = { 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xa, 0xb, 0xc, 0xd,
				0xe, 0xf };
		s.addKey("encrypt-key", keybytes, 0);
		s.addKey("decrypt-key", keybytes, 0);
		OneTimePadCipher cipher = new OneTimePadCipher(s);
		byte[] encrypted = cipher.encrypt("encrypt-key", original);
		String decrypted = cipher.decrypt("decrypt-key", 0, encrypted);
		assertEquals("The original test did not match the decrypted text",
				original, decrypted);
	}


	public void testNullInput() throws EncryptionException {
		try {
			byte[] keybytes = { 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xa, 0xb, 0xc,
					0xd, 0xe, 0xf };
			InMemoryKeyStore s = new InMemoryKeyStore();
			String original = null;
			s.addKey("encrypt-key", keybytes, 0);
			s.addKey("decrypt-key", keybytes, 0);
			OneTimePadCipher cipher = new OneTimePadCipher(s);
			// should fail
			@SuppressWarnings("unused")
			byte[] encrypted = cipher.encrypt("encrypt-key", original);
			fail("IllegalArgumentException should have been thrown.");
		} catch (CipherException e) {
			// should be thrown
		}
	}

	public void testInputOverrun() {

	}

	public void testRandomDataAndKeys() throws EncryptionException {
		Random r = new SecureRandom();
		OneTimePadCipher cipher = new OneTimePadCipher(store);
		byte[] key = new byte[100];
		byte[] input = new byte[100];
		for (int i = 0; i < 100000; i++) {
			r.nextBytes(key);
			r.nextBytes(input);
			byte[] encrypted = cipher.encrypt(input, key);
			String b64encoded = BaseUtils.bytesToBase64(encrypted);
			byte[] b64decoded = BaseUtils.base64ToBytes(b64encoded);
			byte[] decrypted = cipher.decrypt(b64decoded, key);
			assertTrue("The input and decrypted result do not match.", Arrays
					.equals(input, decrypted));
		}
	}

	public void testBase64EncodeDecode() throws EncryptionException {
		String original = "Hello, Again";
		byte[] keybytes = { 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0xa, 0xb, 0xc, 0xd,
				0xe, 0xf };
		InMemoryKeyStore s = new InMemoryKeyStore();
		s.addKey("encrypt-key", keybytes, 0);
		s.addKey("decrypt-key", keybytes, 0);
		
		OneTimePadCipher cipher = new OneTimePadCipher(s);
		byte[] encrypted = cipher.encrypt("encrypt-key",  original);
		String b64encoded = BaseUtils.bytesToBase64(encrypted);
		byte[] b64decoded = BaseUtils.base64ToBytes(b64encoded);
		String decrypted = cipher.decrypt("decrypt-key", 0, b64decoded);
		assertEquals("The original test did not match the decrypted text",
				original, decrypted);

	}
	
	public void testChunkingOne() throws EncodingException {
		byte[] test = { (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee};
		SimpleBase16Encoder encoder = new SimpleBase16Encoder();
		encoder.setMinorChunkSeparator(" ");
		String result = encoder.encode(test);
		assertEquals("Input did not match output", "AA BB CC DD EE\n", result);
	}
	
	public void testChunkingTwo() throws EncodingException {
		byte[] test = { (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88};
		SimpleBase16Encoder encoder = new SimpleBase16Encoder();
		encoder.setMinorChunkSeparator(" ");
		String result = encoder.encode(test);
		assertEquals("Input did not match output", "11 22 33 44 55 66 77 88\n", result);
	}
	
}
