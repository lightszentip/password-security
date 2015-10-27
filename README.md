# README #

http://lightszentip.github.io/password-security/

[![Build Status](https://travis-ci.org/lightszentip/password-security.svg?branch=master)](https://travis-ci.org/lightszentip/password-security)

## Getting Started ##

If you use maven, you need a maven build from the project. Then you can use the following dependency:

    <groupId>com.lightszentip.module</groupId>
	<artifactId>password-security</artifactId>
	<version>1.0.0-RELEASE</version>


The artifact is in the maven central repository.

## Use it ##

Example application https://github.com/lightszentip/password-security-example-app

**First**

Create a new instance of "PasswordModule":

    PasswordModule passwordModule = new PasswordModuleImpl(String secretId, String secretSaltPw, String secureSaltKey, EncryptionType typeEncrypt, AlgorithmType typeEncod, int randomPasswordLength)

> secretId - Salt value for encryption and encoding
> secretSaltPw - Salt value for password encoding
> secureSaltKey - Salt value for encryption
> typeEncrypt - Type for encryption
> typeEncod - Type for encoding
> randomPasswordLength - Length for fake passwords (honeywords)

**Functions**
    
This function generate a random password:

    public String generateRandomPassword(int length);

This function generate a password with encryption and encoding:
    
    public String getCodePassword(String password)

This function generate a password with encryption and encoding and fake passwords:

    public String[] getHoneyPasswordList(String password, int size)

This function checks, is the variable password the right password. For this you need the whole list from  "getHoneyPasswordList":

    checkPassword(String[] passwordArray, String password)

If you want to encryption other values, you can use the following functions:

    public String encrypt(String value, String key, EncryptionType type);
    public String decrypt(String value, String key, EncryptionType type);

**Example**

    PasswordModule passwordEncoder = new PasswordModuleImpl("secretid", "salt", "ThisIsaSaltValue", EncryptionType.AES, AlgorithmType.SHA_512, 20);
    String[] passwordArray = passwordEncoder.getHoneyPasswordList("test", values);
    Assert.assertTrue(passwordEncoder.checkPassword(passwordArray, passwordEncoder.getCodePassword("test")));

## java.security.InvalidKeyException: Illegal key size or default parameters ##

If you get the exception, then you need to download "Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files".


[![Bitdeli Badge](https://d2weczhvl823v0.cloudfront.net/lightszentip/password-security/trend.png)](https://bitdeli.com/free "Bitdeli Badge")

