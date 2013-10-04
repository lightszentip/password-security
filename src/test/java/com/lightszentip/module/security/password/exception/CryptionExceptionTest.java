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
package com.lightszentip.module.security.password.exception;

import org.junit.Assert;
import org.junit.Test;

import com.lightszentip.module.security.password.exception.CryptionException;

public class CryptionExceptionTest {

    @Test
    public void testCryptionException() {
        CryptionException e = new CryptionException("test",new Exception());
        Assert.assertEquals("Exception by crypt method with test", e.getMessage());
    }

}
