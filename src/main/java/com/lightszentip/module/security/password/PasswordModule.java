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

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;

import com.lightszentip.module.security.password.util.EncryptionType;

public interface PasswordModule {

    /**
     * Password check
     * 
     * @param passwordArray
     * @param password
     * @return
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public boolean checkPassword(String[] passwordArray, String password) throws UnsupportedEncodingException, GeneralSecurityException;

    /**
     * Decrtypt a value
     * @param value
     * @param key
     * @param type
     * @return
     */
    public String decrypt(String value, String key, EncryptionType type);

    /**
     * Encrypt a value
     * @param value
     * @param key
     * @param type
     * @return
     */
    public String encrypt(String value, String key, EncryptionType type);

    /**
     * 
     * @param length
     * @return
     */
    public String generateRandomPassword(int length);

    /**
     * Get password as code password
     * 
     * @param password
     * @return
     * @throws UnsupportedEncodingException
     * @throws GeneralSecurityException
     */
    public String getCodePassword(String password) throws UnsupportedEncodingException, GeneralSecurityException;

    /**
     * Generate password list
     * 
     * @param password
     * @param size
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public String[] getHoneyPasswordList(String password, int size) throws NoSuchAlgorithmException, UnsupportedEncodingException;

}