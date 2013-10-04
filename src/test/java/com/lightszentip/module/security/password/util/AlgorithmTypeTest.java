/** 
 * Copyright 2013 Tobias Gafner
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *     
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.lightszentip.module.security.password.util;

import org.junit.Assert;
import org.junit.Test;

import com.lightszentip.module.security.password.util.AlgorithmType;

public class AlgorithmTypeTest {

	@Test
	public void testGetTextMD5() {
		Assert.assertNotNull(AlgorithmType.MD5.getText());
	}
	
	@Test
	public void testGetTextSHA1() {
		Assert.assertNotNull(AlgorithmType.SHA_1.getText());
	}
	
	@Test
	public void testGetTextSHA256() {
		Assert.assertNotNull(AlgorithmType.SHA_256.getText());
	}
	
	@Test
	public void testGetTextSHA384() {
		Assert.assertNotNull(AlgorithmType.SHA_384.getText());
	}
	
	@Test
	public void testGetTextSHA512() {
		Assert.assertNotNull(AlgorithmType.SHA_512.getText());
	}

}
