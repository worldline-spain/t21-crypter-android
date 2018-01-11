# T21 Crypter Library for Android

[![Bintray](https://api.bintray.com/packages/worldline-spain/maven/t21_crypter_android/images/download.svg)](https://bintray.com/worldline-spain/maven/t21_crypter_android/_latestVersion)

This library allows to encrypt and decrypt sensible data in your applications.
Tipically used for token encryption, if you want to secure your application and ensure anyone can steal the token of your users, you should use this library.

## Supported data types
- String

## Features
- Encryption (AES/CBC/PKCS5Padding) with a random IV
- Decryption (AES/CBC/PKCS5Padding)

## Import:

- Maven
```xml
dependency>
  <groupId>com.tempos21.t21crypt</groupId>
  <artifactId>t21_crypter_android</artifactId>
  <version>1.0.5</version>
  <type>pom</type>
</dependency>
````
- Gradle
```xml
compile 'com.tempos21.t21crypt:t21_crypter_android:1.0.5'
```
- Ivy
```xml
<dependency org='com.tempos21.t21crypt' name='t21_crypter_android' rev='1.0.5'>
  <artifact name='$AID' ext='pom'></artifact>
</dependency>
```

## Usage:

Encryption:

```java
/**
 * This key should be dynamic
 */
private static final String KEY_TOKEN = "RANDOM_STRING";

String textToEncrypt = "whatIWantToCrypt1234";
final Crypter crypter = CrypterFactory.buildCrypter(CryptMethod.AES, KEY_TOKEN);
String encryptedText = crypter.encrypt(textToEncrypt);
```

Decryption:

```java
/**
 * This key should be dynamic
 */
private static final String KEY_TOKEN = "RANDOM_STRING";

String textToDecrypt = "rAvceqEKRR3uG7jltp7EccfMobmipUgvp142pnmQB2g=";
final Crypter crypter = CrypterFactory.buildCrypter(CryptMethod.AES, KEY_TOKEN);
String decryptedText = crypter.decrypt(textToDecrypt);
```

# Contributing to the project

Feel free to report any issues or suggest new features.

# License

Copyright 2016 Worldline Iberia

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
