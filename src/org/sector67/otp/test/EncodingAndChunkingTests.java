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

import org.sector67.otp.key.FileKeyStore;
import org.sector67.otp.utils.BaseUtils;

import junit.framework.TestCase;

/**
 * Encoding and chunking test suite
 * 
 * @author scott.hasse@gmail.com
 */
public class EncodingAndChunkingTests extends TestCase {
	FileKeyStore store;

	protected void setUp() throws Exception {
		super.setUp();
	}

	protected void tearDown() throws Exception {
		super.tearDown();
	}

	
	public void testChunkingOne() {
		byte[] test = { (byte)0xaa, (byte)0xbb, (byte)0xcc, (byte)0xdd, (byte)0xee};
		String result = BaseUtils.getChunkedBase16(test);
		assertEquals("Input did not match output", "AABB CCDD EE\n", result);
	}
	
	public void testChunkingTwo() {
		byte[] test = { (byte)0x11, (byte)0x22, (byte)0x33, (byte)0x44, (byte)0x55, (byte)0x66, (byte)0x77, (byte)0x88};
		String result = BaseUtils.getChunkedBase16(test);
		assertEquals("Input did not match output", "1122 3344 5566 7788\n", result);
	}
}
