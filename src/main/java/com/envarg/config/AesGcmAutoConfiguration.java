package com.envarg.config;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import com.envarg.config.properties.AesGcmProperties;
import com.envarg.service.AesGcmService;

@AutoConfiguration
@ConditionalOnProperty(prefix = "app.aes-gcm", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AesGcmProperties.class)
@RequiredArgsConstructor
@SuppressWarnings({"PMD.UnusedPrivateField"})
public class AesGcmAutoConfiguration {
  private final AesGcmProperties aesGcmProperties;

  @Bean
  @ConditionalOnMissingBean
  public SecureRandom secureRandom() {
    return new SecureRandom();
  }

  @Bean
  @ConditionalOnMissingBean
  public SecretKey aesGcmSecretKey() {
    byte[] keyBytes = Base64.getDecoder().decode(aesGcmProperties.getSecret());
    if (keyBytes.length != 32) {
      throw new IllegalArgumentException("AES-GCM secret must be 32 bytes (256 bits), got: " + keyBytes.length);
    }
    return new SecretKeySpec(keyBytes, "AES");
  }

  @Bean
  @ConditionalOnMissingBean
  public AesGcmService aesGcmService(SecureRandom secureRandom, SecretKey aesGcmSecretKey, AesGcmProperties properties) {
    return new AesGcmService(secureRandom, aesGcmSecretKey, properties.getVersion());
  }
}
