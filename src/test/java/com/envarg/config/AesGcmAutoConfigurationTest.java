package com.envarg.config;

import javax.crypto.SecretKey;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import com.envarg.service.AesGcmService;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest(classes = AesGcmAutoConfiguration.class)
@TestPropertySource(properties = {
    "app.aes-gcm.enabled=true",
    "app.aes-gcm.secret=rBm/L0MsvQqX2adVQLU072edfzkyCCH0pPTtt+kIL0s=",
    "app.aes-gcm.version=1"
})
class AesGcmAutoConfigurationTest {

  @Autowired
  private AesGcmService aesGcmService;

  @Autowired
  private SecretKey aesGcmSecretKey;

  @Test
  void contextLoads() {
    assertNotNull(aesGcmService);
    assertNotNull(aesGcmSecretKey);
  }

  @Test
  void encryptDecrypt_roundTrip() {
    String plaintext = "hello-world";
    String encrypted = aesGcmService.encrypt(plaintext);
    String decrypted = aesGcmService.decrypt(encrypted);
    
    assertNotNull(encrypted);
    assertEquals(plaintext, decrypted);
  }
}
