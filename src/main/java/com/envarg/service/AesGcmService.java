package com.envarg.service;

import java.security.SecureRandom;
import javax.crypto.SecretKey;
import com.envarg.utils.AesGcmDecoder;

@SuppressWarnings({"PMD.UnusedPrivateField"})
public class AesGcmService {
  private final SecureRandom secureRandom;
  private final SecretKey key;
  private final Integer keyVersion;

  public AesGcmService(SecureRandom secureRandom, SecretKey key, Integer keyVersion) {
    this.secureRandom = secureRandom;
    this.key = key;
    this.keyVersion = keyVersion;
  }
  
  public String encrypt(String plaintext) {
    return AesGcmDecoder.encrypt(plaintext, secureRandom, key, keyVersion);
  }
  
  public String decrypt(String columnValue) {
    return AesGcmDecoder.decrypt(columnValue, key, keyVersion);
  }
}
