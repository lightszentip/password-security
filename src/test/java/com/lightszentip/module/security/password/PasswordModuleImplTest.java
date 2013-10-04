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
package com.lightszentip.module.security.password;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.experimental.theories.DataPoint;
import org.junit.experimental.theories.DataPoints;
import org.junit.experimental.theories.Theories;
import org.junit.experimental.theories.Theory;
import org.junit.rules.TestName;
import org.junit.runner.RunWith;

import com.lightszentip.module.security.password.PasswordModule;
import com.lightszentip.module.security.password.PasswordModuleImpl;
import com.lightszentip.module.security.password.util.AlgorithmType;
import com.lightszentip.module.security.password.util.EncryptionType;

@RunWith(Theories.class)
public class PasswordModuleImplTest {

    @DataPoint
    public static AlgorithmType typeSha1 = AlgorithmType.SHA_1;
    @DataPoint
    public static AlgorithmType typeSha256 = AlgorithmType.SHA_256;
    @DataPoint
    public static AlgorithmType typeSha384 = AlgorithmType.SHA_384;
    @DataPoint
    public static AlgorithmType typeSha512 = AlgorithmType.SHA_512;
    @DataPoint
    public static AlgorithmType typeShaMd5 = AlgorithmType.MD5;
    @DataPoint
    public static EncryptionType typeBlowfish = EncryptionType.BLOWFISH;
    @DataPoint
    public static EncryptionType typeAes = EncryptionType.AES;
    @DataPoint
    public static EncryptionType typeTwofish = EncryptionType.TWOFISH;

    public static @DataPoints
    int[] values = { 2, 3, 4, 6, 9, 15, 1000, 2178 };

    @Rule
    public TestName name = new TestName();

    public PasswordModuleImplTest() {

    }

    @org.junit.Before
    public void setUp() throws Exception {

    }

    @org.junit.After
    public void tearDown() throws Exception {

    }

    @org.junit.Test
    @Theory
    public void testGetEncodePassword(AlgorithmType x, EncryptionType y) throws Exception {
        PasswordModule passwordEncoder = new PasswordModuleImpl("secretid", "salt", "ThisIsaSaltValue", y, x, 100);
        String pwEncoded = passwordEncoder.getCodePassword("test");
        Assert.assertNotNull(pwEncoded);
        Assert.assertNotEquals("test", pwEncoded);
    }

    @org.junit.Test
    public void testGenerateRandomPassword() throws Exception {
        PasswordModule passwordEncoder = new PasswordModuleImpl("secretid", "salt", "ThisIsaSaltValue", typeTwofish, typeSha512, 100);
        Assert.assertEquals(25, passwordEncoder.generateRandomPassword(25).length());
    }

    @org.junit.Test(expected = IllegalArgumentException.class)
    public void testGenerateRandomPasswordIllegalArgumentException() throws Exception {
        PasswordModule passwordEncoder = new PasswordModuleImpl("secretid", "salt", "ThisIsaSaltValue", typeTwofish, typeSha512, 100);
        passwordEncoder.generateRandomPassword(0);
    }
    
    @org.junit.Test(expected = IllegalArgumentException.class)
    public void testPasswordEncoderIllegalArgumentException() throws Exception {
        new PasswordModuleImpl("secret", "salt", "ThisIsaSaltValue", typeTwofish, typeSha512, 100);
    }

    @org.junit.Test
    @Theory
    public void testGetHoneyPasswordList(AlgorithmType x, EncryptionType y, int value) throws Exception {
        PasswordModule passwordEncoder = new PasswordModuleImpl("secretidsecretid", "salt", "ThisIsaSaltValue", y, x, 100);
        String[] passwordArray = passwordEncoder.getHoneyPasswordList("test", value);
        Assert.assertEquals(value, passwordArray.length);
        Assert.assertNotNull(passwordArray[value - 1]);
        for (int i = 0; i < passwordArray.length; i++) {
            for (int j = 0; j < passwordArray.length; j++) {
                if (j != i) {
                    Assert.assertNotEquals(passwordArray[j], passwordArray[i]);
                }
            }
        }
    }

    @org.junit.Test
    @Theory
    public void testCheckPassword(AlgorithmType x, EncryptionType y, int values) throws Exception {
        PasswordModule passwordEncoder = new PasswordModuleImpl("secretid", "salt", "ThisIsaSaltValue", y, x, 20);
        String[] passwordArray = passwordEncoder.getHoneyPasswordList("test", values);
        Assert.assertTrue(passwordEncoder.checkPassword(passwordArray, passwordEncoder.getCodePassword("test")));
    }

}
