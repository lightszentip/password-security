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

import com.lightszentip.module.security.password.util.EncryptionType;

public class EncryptionTypeTest {

	@Test
	public void testGetTextBlowFish() {
		Assert.assertNotNull(EncryptionType.BLOWFISH.getText());
	}
	
	@Test
	public void testGetTextAES() {
		Assert.assertNotNull(EncryptionType.AES.getText());
	}
	
	@Test
	public void testGetTextTwoFish() {
		Assert.assertNotNull(EncryptionType.TWOFISH.getText());
	}

}
