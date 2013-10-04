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
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.lightszentip.module.security.password.exception.CryptionException;
import com.lightszentip.module.security.password.util.AlgorithmType;
import com.lightszentip.module.security.password.util.EncryptionType;

public final class PasswordModuleImpl implements PasswordModule {

    private AlgorithmType typeEncod;

    private EncryptionType typeEncrypt;

    private String secretId;

    private String secretSaltPw;

    private static final int HONEYNUMBER = 100;

    private String disconnector = ".";

    private String key;

    private int randomPasswordLength;

    /**
     * Constructor Set attribute for password encoding and cryption, for
     * generate and check - you need the same attributes
     * 
     * @param secretId
     * @param secretSaltPw
     * @param secureSaltKey
     * @param typeEncrypt
     * @param typeEncod
     * @param randomPasswordLength
     */
    public PasswordModuleImpl(String secretId, String secretSaltPw, String secureSaltKey, EncryptionType typeEncrypt, AlgorithmType typeEncod, int randomPasswordLength) {
        this.secretId = secretId;
        this.secretSaltPw = secretSaltPw;
        this.typeEncod = typeEncod;
        this.typeEncrypt = typeEncrypt;
        this.randomPasswordLength = randomPasswordLength;
        this.key = secureSaltKey + this.secretId;
        if (this.key.length() % 4 != 0) {
            throw new IllegalArgumentException("The length for secureSaltKey and secretId is false");
        }
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean checkPassword(String[] passwordArray, String password) throws UnsupportedEncodingException, GeneralSecurityException {
        int counter = 0;
        String[] pwEncrypted = new String[passwordArray.length];
        for (int i = 0; i < passwordArray.length; i++) {
            pwEncrypted[i] = decrypt(passwordArray[i], key, typeEncrypt);
            counter += Integer.valueOf(pwEncrypted[i].substring(0, pwEncrypted[i].indexOf(disconnector)));
        }
        int numberPassword = 0;
        if (counter > 0) {
            numberPassword = getNumberPassword(counter, passwordArray.length);
        }
        return pwEncrypted[numberPassword].substring(pwEncrypted[numberPassword].indexOf(disconnector) + 1).equals(decrypt(password, key, typeEncrypt));

    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String decrypt(String value, String key, EncryptionType type) {
        return crypt(value, key, type, Cipher.DECRYPT_MODE);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String encrypt(String value, String key, EncryptionType type) {
        return crypt(value, key, type, Cipher.ENCRYPT_MODE);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String generateRandomPassword(int length) {
        return generate(length);
    }
    
    /**
     * {@inheritDoc}
     */
    @Override
    public String[] getHoneyPasswordList(String password, int size) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        String[] passwordArray = new String[size];
        int randomNumber = generateRandom(0, size - 2);
        int counter = getCounter(randomNumber, size);
        counter = counter - randomNumber;
        setPasswordArrayValue(randomNumber, randomNumber, passwordArray, password);
        for (int i = 0; i < (size - 1); i++) {
            if (i != randomNumber) {
                int y = 0;
                int max = counter - (size - i);
                do {
                    y = generateRandom(0, max);
                } while (randomNumber == y || ((counter - y) == randomNumber));
                counter = counter - y;
                setPasswordArrayValue(i, y, passwordArray, generateRandomPassword(this.randomPasswordLength));
            }
        }
        setPasswordArrayValue(size - 1, counter, passwordArray, generateRandomPassword(this.randomPasswordLength));
        return passwordArray;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String getCodePassword(String password) throws UnsupportedEncodingException, GeneralSecurityException {
        return encrypt(encode(password, typeEncod), key, typeEncrypt);
    }
    
    private String encode(String pass, AlgorithmType type) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] digested = hashPwd(this.secretSaltPw + pass + this.secretId, type);
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < digested.length; i++) {
            sb.append(Integer.toHexString(0xff & digested[i]));
        }
        return sb.toString();
    }

    private int getCounter(final int numberPassword, final int length) {
        return ((2 * (HONEYNUMBER * length)) - length) - (numberPassword);
    }

    private int getNumberPassword(final int counter, final int length) {
        return (((2 * (HONEYNUMBER * length)) - length) - counter);
    }
    
    private int generateRandom(int min, int max) {
        return (int) (Math.random() * (max + 1 - min) + min);
    }

    private byte[] hashPwd(String password, AlgorithmType algorithm) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md = null;
        if (AlgorithmType.MD5.equals(algorithm)) {
            md = DigestUtils.getMd5Digest();
        } else if (AlgorithmType.SHA_512.equals(algorithm)) {
            md = DigestUtils.getSha512Digest();
        } else if (AlgorithmType.SHA_384.equals(algorithm)) {
            md = DigestUtils.getSha384Digest();
        } else if (AlgorithmType.SHA_256.equals(algorithm)) {
            md = DigestUtils.getSha256Digest();
        } else if (AlgorithmType.SHA_1.equals(algorithm)) {
            md = DigestUtils.getSha1Digest();
        }
        md.update(password.getBytes());
        return md.digest();
    }

    private void setPasswordArrayValue(int pwPos, int pwNumber, String[] passwordArray, String password) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        passwordArray[pwPos] = encrypt(pwNumber + disconnector + this.encode(password, this.typeEncod), key, typeEncrypt);
    }
    
    private String generate(int length) {
        String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String special = "!\"#$%&'()*+,-./:;<=>?@{}%§";
        if (length == 0) {
            throw new IllegalArgumentException("At least one alphabet must be given");
        }
        StringBuffer result = new StringBuffer();
        String letters = alphabet + digits + special;
        for (int i = 0; i < length; i++) {
            int randomNumber = generateRandom(0, 2);
            if (randomNumber > 1) {
                result.append(letters.charAt(generateRandom(0, letters.length() - 1)));
            } else if (randomNumber == 1) {
                result.append(special.charAt(generateRandom(0, special.length() - 1)));
            } else {
                result.append(digits.charAt(generateRandom(0, digits.length() - 1)));
            }
        }
        return result.toString();
    }
    
    private String crypt(String value, String key, EncryptionType type, int optmode) {
        try {
            Cipher cipher = Cipher.getInstance(type.getText());
            String passwordSecret = null;
            cipher.init(optmode, new SecretKeySpec((key).getBytes(), type.getText()));
            if (optmode == Cipher.ENCRYPT_MODE) {
                passwordSecret = Base64.encodeBase64String(cipher.doFinal(value.getBytes()));
            } else {
                passwordSecret = new String(cipher.doFinal(Base64.decodeBase64(value)));
            }
            return passwordSecret;
        } catch (InvalidKeyException e) {
            throw new CryptionException(e.getMessage(), e);
        } catch (IllegalBlockSizeException e) {
            throw new CryptionException(e.getMessage(), e);
        } catch (BadPaddingException e) {
            throw new CryptionException(e.getMessage(), e);
        } catch (NoSuchAlgorithmException e) {
            throw new CryptionException(e.getMessage(), e);
        } catch (NoSuchPaddingException e) {
            throw new CryptionException(e.getMessage(), e);
        }
    }

}
